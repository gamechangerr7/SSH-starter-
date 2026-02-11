#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------
USERS=()

SSH_PORT=2233
CIPHERS="aes128-gcm@openssh.com,aes128-ctr"
UDPGW_PORT=7305
STEP_DELAY=1

# ------------------------------------------------------------
# HELPER FUNCTIONS
# ------------------------------------------------------------
info() { echo -e "\n\033[1;34m[INFO]\033[0m $1"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $1"; }
err()  { echo -e "\033[1;31m[ERROR]\033[0m $1" >&2; }
success() { echo -e "\033[1;32m[✔]\033[0m $1"; }
fail() { echo -e "\033[1;31m[✘]\033[0m $1"; }

parse_users_arg() {
    local raw="$1"
    local cleaned=()
    local u

    if [[ -z "${raw}" ]]; then
        err "Missing users list. Example: $0 users name1,anothername"
        exit 1
    fi

    IFS=',' read -r -a USERS <<<"$raw"

    for u in "${USERS[@]}"; do
        u="${u#${u%%[![:space:]]*}}"
        u="${u%${u##*[![:space:]]}}"
        if [[ -n "$u" ]]; then
            cleaned+=("$u")
        fi
    done

    if [[ ${#cleaned[@]} -eq 0 ]]; then
        err "No valid users found in list: '$raw'"
        exit 1
    fi

    USERS=("${cleaned[@]}")
}

parse_port_arg() {
    local raw="$1"

    if [[ -z "${raw}" ]]; then
        return 0
    fi

    if [[ ! "$raw" =~ ^[0-9]+$ ]]; then
        err "Invalid port: '$raw' (must be a number)"
        exit 1
    fi

    if (( raw < 1 || raw > 65535 )); then
        err "Invalid port: '$raw' (must be 1-65535)"
        exit 1
    fi

    SSH_PORT="$raw"
}

run_with_sudo() {
    if [[ $EUID -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

# ------------------------------------------------------------
# STEP 1: CREATE USERS
# ------------------------------------------------------------
add_users() {
    info "Adding system users..."
    for u in "${USERS[@]}"; do
        if id "$u" &>/dev/null; then
            echo "  $u : already exists"
        else
            run_with_sudo useradd -m -s /bin/bash "$u"
            echo "$u:$u" | run_with_sudo chpasswd
            echo "  $u : user added with password '$u'"
        fi
    done
}

# ------------------------------------------------------------
# STEP 2: CONFIGURE SSHD (port + ciphers) & RESTART
# ------------------------------------------------------------
configure_ssh() {
    info "Configuring SSH (port $SSH_PORT, ciphers)..."
    local sshd_config="/etc/ssh/sshd_config"
    local backup="${sshd_config}.bak.$(date +%Y%m%d%H%M%S)"

    if [[ ! -f "$sshd_config" ]]; then
        err "$sshd_config not found!"
        return 1
    fi

    run_with_sudo cp "$sshd_config" "$backup"
    info "Backup created: $backup"

    if run_with_sudo grep -qE '^#?Port\s+' "$sshd_config"; then
        run_with_sudo sed -i "s/^#\?Port\s\+.*/Port $SSH_PORT/" "$sshd_config"
    else
        echo "Port $SSH_PORT" | run_with_sudo tee -a "$sshd_config" >/dev/null
    fi

    if run_with_sudo grep -qE '^#?Ciphers\s+' "$sshd_config"; then
        run_with_sudo sed -i "s/^#\?Ciphers\s\+.*/Ciphers $CIPHERS/" "$sshd_config"
    else
        echo "Ciphers $CIPHERS" | run_with_sudo tee -a "$sshd_config" >/dev/null
    fi

    info "Restarting SSH service..."
    run_with_sudo systemctl restart ssh || run_with_sudo systemctl restart sshd
    success "SSH configured on port $SSH_PORT"
}

# ------------------------------------------------------------
# STEP 3: RUN RECAPTCHA SCRIPT (install_kernel.sh, first pass)
# answers: 1 (English), 12, y, y, 1
# ------------------------------------------------------------
run_recaptcha() {
    info "Downloading install_kernel.sh (reCAPTCHA phase) if missing..."
    if [[ ! -f install_kernel.sh ]]; then
        curl -O https://raw.githubusercontent.com/jinwyp/one_click_script/master/install_kernel.sh
        chmod +x install_kernel.sh
    fi

    info "Running install_kernel.sh with full output (log: /tmp/recaptcha.log)..."
    local answers="1\n12\ny\ny\n1\n"
    if command -v stdbuf &>/dev/null; then
        printf "%b" "$answers" | stdbuf -oL -eL ./install_kernel.sh 2>&1 | tee /tmp/recaptcha.log
    else
        printf "%b" "$answers" | ./install_kernel.sh 2>&1 | tee /tmp/recaptcha.log
    fi
    success "reCAPTCHA part completed."
}

# ------------------------------------------------------------
# STEP 4A: UDPGW PORT CHANGE – SILENT BACKGROUND + CLEAR VERIFICATION
# ------------------------------------------------------------
run_udgpw() {
    local env_file="/var/www/html/app/.env"
    local badvpn_dir="/root/badvpn"
    local build_dir="/root/badvpn/badvpn-build"
    local current_line=""
    local final_line=""

    info "Current UDPGW listen:"
    if command -v ss &>/dev/null; then
        current_line=$(ss -tulpn 2>/dev/null | grep -F "badvpn-udpgw" || true)
    elif command -v netstat &>/dev/null; then
        current_line=$(netstat -tulpn 2>/dev/null | grep -F "badvpn-udpgw" || true)
    fi
    echo "  ${current_line:-not listening}"

    info "Installing/rebuilding badvpn-udpgw on port $UDPGW_PORT..."

    if systemctl list-units --full -all | grep -Fq 'videocall.service'; then
        if systemctl is-active videocall &>/dev/null; then
            run_with_sudo systemctl stop videocall
        fi
    fi
    for _ in {1..10}; do
        if ! pgrep -x badvpn-udpgw &>/dev/null; then
            break
        fi
        sleep 1
    done
    if pgrep -x badvpn-udpgw &>/dev/null; then
        run_with_sudo pkill -TERM badvpn-udpgw || true
        sleep 1
        run_with_sudo pkill -KILL badvpn-udpgw || true
    fi
    if command -v fuser &>/dev/null; then
        run_with_sudo fuser -k /usr/local/bin/badvpn-udpgw || true
    fi

    if [[ -f "$env_file" ]]; then
        run_with_sudo sed -i "s/PORT_UDPGW=.*/PORT_UDPGW=$UDPGW_PORT/g" "$env_file"
    fi

    run_with_sudo apt update -y
    run_with_sudo apt install git cmake -y

    if [[ ! -d "$badvpn_dir/.git" ]]; then
        run_with_sudo git clone https://github.com/ambrop72/badvpn.git "$badvpn_dir"
    else
        run_with_sudo git -C "$badvpn_dir" pull --ff-only
    fi

    run_with_sudo mkdir -p "$build_dir"
    run_with_sudo bash -c "cd '$build_dir' && cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1"
    run_with_sudo bash -c "cd '$build_dir' && make"
    run_with_sudo install -m 0755 "$build_dir/udpgw/badvpn-udpgw" /usr/local/bin/badvpn-udpgw.new
    run_with_sudo mv -f /usr/local/bin/badvpn-udpgw.new /usr/local/bin/badvpn-udpgw

    run_with_sudo tee /etc/systemd/system/videocall.service >/dev/null <<EOF
[Unit]
Description=UDP forwarding for badvpn-tun2socks
After=nss-lookup.target

[Service]
ExecStart=/usr/local/bin/badvpn-udpgw --loglevel none --listen-addr 127.0.0.1:$UDPGW_PORT --max-clients 999
User=videocall

[Install]
WantedBy=multi-user.target
EOF

    if ! id videocall &>/dev/null; then
        run_with_sudo useradd -m videocall
    fi

    run_with_sudo systemctl daemon-reload
    run_with_sudo systemctl enable videocall
    run_with_sudo systemctl restart videocall

    if [[ -f "$env_file" ]]; then
        run_with_sudo sed -i "s/PORT_UDPGW=.*/PORT_UDPGW=$UDPGW_PORT/g" "$env_file"
    fi

    info "After change:"
    if command -v ss &>/dev/null; then
        final_line=$(ss -tulpn 2>/dev/null | grep "$UDPGW_PORT" || true)
    elif command -v netstat &>/dev/null; then
        final_line=$(netstat -tulpn 2>/dev/null | grep "$UDPGW_PORT" || true)
    fi
    echo "  ${final_line:-not listening}"

    success "UDPGW rebuilt and started on port $UDPGW_PORT."
}

# ------------------------------------------------------------
# STEP 4B: ENABLE BBR (install_kernel.sh, second pass)
# answers: 2, 2, 4, y, y
# ------------------------------------------------------------
run_bbr() {
    info "Enabling BBR (via install_kernel.sh)..."
    if [[ ! -f install_kernel.sh ]]; then
        curl -O https://raw.githubusercontent.com/jinwyp/one_click_script/master/install_kernel.sh
        chmod +x install_kernel.sh
    fi

    echo -e "2\n2\n4\ny\ny\n" | ./install_kernel.sh
    success "BBR enabled."
}

# ------------------------------------------------------------
# STEP ALL: RUN EVERYTHING IN ORDER
# ------------------------------------------------------------
run_all() {
    info "STEP 1/5: users"
    add_users
    sleep "$STEP_DELAY"

    info "STEP 2/5: ssh"
    configure_ssh
    sleep "$STEP_DELAY"

    info "STEP 3/5: recaptcha"
    run_recaptcha
    sleep "$STEP_DELAY"

    info "STEP 4/5: udgpw"
    run_udgpw
    sleep "$STEP_DELAY"

    info "STEP 5/5: bbr"
    run_bbr
    info "All steps completed successfully!"
}

# ------------------------------------------------------------
# MAIN DISPATCH
# ------------------------------------------------------------
usage() {
    cat <<EOF
Usage: $0 {users|ssh|recaptcha|udgpw|bbr|all} [port] [users_list]

  users      - Create users from list (comma-separated)
  ssh        - Change SSH port (default $SSH_PORT) and set ciphers
  recaptcha  - Run install_kernel.sh (reCAPTCHA step)
  udgpw      - Set UDPGW port to $UDPGW_PORT (silent, auto‑correct)
  bbr        - Enable BBR (install_kernel.sh second pass)
  all        - Execute all steps in the correct order (requires users list)

Example:
  $0 users name1,anothername
  $0 ssh 2233
  $0 all 2233 name1,anothername
  $0 all name1,anothername
EOF
}

if [[ $# -eq 0 ]]; then
    usage
    exit 1
fi

case "$1" in
    users)      parse_users_arg "${2-}"; add_users ;;
    ssh)        parse_port_arg "${2-}"; configure_ssh ;;
    recaptcha)  run_recaptcha ;;
    udgpw)      run_udgpw ;;
    bbr)        run_bbr ;;
    all)
        if [[ "${2-}" =~ ^[0-9]+$ ]]; then
            parse_port_arg "${2-}"
            parse_users_arg "${3-}"
        else
            parse_users_arg "${2-}"
        fi
        run_all
        ;;
    *)          warn "Unknown command: $1"; usage; exit 1 ;;
esac
