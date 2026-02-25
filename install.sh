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
DETECTED_SSH_PORT=""
DETECTED_SSH_PORT_SOURCE=""
DETECTED_IRAN_IP=""
DETECTED_IRAN_IP_SOURCE=""

# ------------------------------------------------------------
# HELPER FUNCTIONS
# ------------------------------------------------------------
info() { echo -e "\n\033[1;34m[INFO]\033[0m $1"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $1"; }
err()  { echo -e "\033[1;31m[ERROR]\033[0m $1" >&2; }
success() { echo -e "\033[1;32m[✔]\033[0m $1"; }
fail() { echo -e "\033[1;31m[✘]\033[0m $1"; }

show_sshtunnel_banner() {
    echo -e "\033[1;35m"
    cat <<'EOF'
==========================================================
   _____ ____  _    _   _______ _   _ _   _ ______ _     
  / ____/ __ \| |  | | |__   __| \ | | \ | |  ____| |    
 | (___| |  | | |  | |    | |  |  \| |  \| | |__  | |    
  \___ \ |  | | |  | |    | |  | . ` | . ` |  __| | |    
  ____) | |__| | |__| |    | |  | |\  | |\  | |____| |____
 |_____/ \____/ \____/     |_|  |_| \_|_| \_|______|______|
==========================================================
EOF
    echo -e "\033[0m"
}

parse_users_arg() {
    local raw="$1"
    local cleaned=()
    local u

    if [[ -z "${raw}" ]]; then
        err "Missing users list. Example: $0 users shayan,anothername"
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

is_valid_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 ))
}

prompt_with_default() {
    local label="$1"
    local default="$2"
    local value=""
    read -r -p "$(printf '\033[1;36m%s\033[0m [%s] (Enter=use default): ' "$label" "$default")" value
    echo "${value:-$default}"
}

prompt_yes_no() {
    local label="$1"
    local default="${2:-n}"
    local value=""
    local suffix="[y/N]"

    if [[ "${default,,}" == "y" ]]; then
        suffix="[Y/n]"
    fi

    read -r -p "$(printf '\033[1;36m%s\033[0m %s: ' "$label" "$suffix")" value
    value="${value,,}"
    if [[ -z "$value" ]]; then
        value="${default,,}"
    fi

    [[ "$value" == "y" || "$value" == "yes" ]]
}

detect_current_ssh_port() {
    local detected=""
    local source=""

    if command -v ss &>/dev/null; then
        detected="$(run_with_sudo ss -tlnp 2>/dev/null | awk '
            /LISTEN/ && /sshd/ {
                addr=$4
                gsub(/\[|\]/, "", addr)
                n=split(addr, parts, ":")
                p=parts[n]
                if (p ~ /^[0-9]+$/) { print p; exit }
            }' || true)"
        if is_valid_port "${detected:-}"; then
            source="ss -tlnp (sshd)"
        fi
    fi

    if ! is_valid_port "${detected:-}" && command -v sshd &>/dev/null; then
        detected="$(run_with_sudo sshd -T 2>/dev/null | awk '/^port / {print $2; exit}' || true)"
        if is_valid_port "${detected:-}"; then
            source="sshd -T"
        fi
    fi

    if ! is_valid_port "${detected:-}"; then
        detected="$(run_with_sudo awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/ {print $2; exit}' /etc/ssh/sshd_config 2>/dev/null || true)"
        if is_valid_port "${detected:-}"; then
            source="/etc/ssh/sshd_config"
        fi
    fi

    if ! is_valid_port "${detected:-}"; then
        detected=""
        source=""
    fi

    DETECTED_SSH_PORT="$detected"
    DETECTED_SSH_PORT_SOURCE="$source"
    [[ -n "$detected" ]]
}

detect_public_ipv4() {
    local ip=""

    DETECTED_IRAN_IP=""
    DETECTED_IRAN_IP_SOURCE=""

    if command -v curl &>/dev/null; then
        ip="$(curl -4fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
        if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            DETECTED_IRAN_IP="$ip"
            DETECTED_IRAN_IP_SOURCE="api.ipify.org"
            return 0
        fi

        ip="$(curl -4fsS --max-time 5 https://ifconfig.me 2>/dev/null || true)"
        if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            DETECTED_IRAN_IP="$ip"
            DETECTED_IRAN_IP_SOURCE="ifconfig.me"
            return 0
        fi
    fi

    if command -v ip &>/dev/null; then
        ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}' || true)"
        if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            DETECTED_IRAN_IP="$ip"
            DETECTED_IRAN_IP_SOURCE="ip route get"
            return 0
        fi

        ip="$(ip -4 -o addr show scope global up 2>/dev/null | awk 'NR==1 {print $4}' | cut -d/ -f1 || true)"
        if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            DETECTED_IRAN_IP="$ip"
            DETECTED_IRAN_IP_SOURCE="ip -4 addr"
            return 0
        fi
    fi

    if command -v hostname &>/dev/null; then
        ip="$(hostname -I 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/) {print $i; exit}}' || true)"
        if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            DETECTED_IRAN_IP="$ip"
            DETECTED_IRAN_IP_SOURCE="hostname -I"
            return 0
        fi
    fi

    return 1
}

resolve_ipv4() {
    local host="$1"
    local ip=""

    if [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "$host"
        return 0
    fi

    if command -v getent &>/dev/null; then
        ip="$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1 {print $1}' || true)"
    fi

    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "$ip"
        return 0
    fi

    return 1
}

show_sshtunnel_commands() {
    local iran_ip="$1"
    local iran_port="$2"
    local eu_ip="$3"
    local eu_port="$4"
    local blacklist_ip="${5:-}"

    echo
    echo "Commands to be executed on this server:"
    echo "sudo sysctl -w net.ipv4.ip_forward=1"
    echo "sudo iptables -F"
    echo "sudo iptables -t nat -F"
    echo "sudo iptables -X"

    if [[ -n "$blacklist_ip" ]]; then
        echo "sudo iptables -t nat -I PREROUTING 1 -s $blacklist_ip -p tcp --dport $iran_port -j RETURN"
        echo "sudo iptables -t nat -I PREROUTING 1 -s $blacklist_ip -p udp --dport $iran_port -j RETURN"
    fi

    echo "sudo iptables -t nat -A PREROUTING -p tcp -d $iran_ip --dport $iran_port -j DNAT --to-destination $eu_ip:$eu_port"
    echo "sudo iptables -t nat -A PREROUTING -p udp -d $iran_ip --dport $iran_port -j DNAT --to-destination $eu_ip:$eu_port"
    echo "sudo iptables -t nat -A POSTROUTING -p tcp -d $eu_ip --dport $eu_port -j MASQUERADE"
    echo "sudo iptables -t nat -A POSTROUTING -p udp -d $eu_ip --dport $eu_port -j MASQUERADE"
    echo "sudo iptables -A FORWARD -p tcp -d $eu_ip --dport $eu_port -j ACCEPT"
    echo "sudo iptables -A FORWARD -p udp -d $eu_ip --dport $eu_port -j ACCEPT"
    echo "sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    echo
}

ensure_root_cron_job() {
    local cron_line="$1"
    local current_cron=""
    local header_1="# ==== SSH Tunnel Auto-Restore (managed by install.sh) ===="
    local header_2="# Added by command: ./install.sh sshtunnel"

    current_cron="$(run_with_sudo crontab -l 2>/dev/null || true)"
    if grep -Fqx "$cron_line" <<<"$current_cron"; then
        info "Root crontab already contains reboot entry."
        return 0
    fi

    {
        [[ -n "$current_cron" ]] && printf '%s\n' "$current_cron"
        if [[ -n "$current_cron" ]]; then
            printf '\n'
        fi
        if ! grep -Fqx "$header_1" <<<"$current_cron"; then
            printf '%s\n' "$header_1"
            printf '%s\n' "$header_2"
        fi
        printf '%s\n' "$cron_line"
    } | run_with_sudo crontab -

    success "Root crontab updated for reboot."
}

write_sshtunnel_reboot_script() {
    local iran_ip="$1"
    local iran_port="$2"
    local eu_ip="$3"
    local eu_port="$4"
    local blacklist_ip="${5:-}"
    local script_path="/usr/local/sbin/sshtunnel-restore.sh"
    local blacklist_tcp_rule=""
    local blacklist_udp_rule=""

    if [[ -n "$blacklist_ip" ]]; then
        blacklist_tcp_rule="\"\$IPTABLES_BIN\" -t nat -I PREROUTING 1 -s $blacklist_ip -p tcp --dport $iran_port -j RETURN"
        blacklist_udp_rule="\"\$IPTABLES_BIN\" -t nat -I PREROUTING 1 -s $blacklist_ip -p udp --dport $iran_port -j RETURN"
    fi

    run_with_sudo tee "$script_path" >/dev/null <<EOF
#!/usr/bin/env bash
set -euo pipefail

IPTABLES_BIN="\$(command -v iptables || echo /sbin/iptables)"
SYSCTL_BIN="\$(command -v sysctl || echo /sbin/sysctl)"

"\$SYSCTL_BIN" -w net.ipv4.ip_forward=1 >/dev/null
"\$IPTABLES_BIN" -F
"\$IPTABLES_BIN" -t nat -F
"\$IPTABLES_BIN" -X
${blacklist_tcp_rule}
${blacklist_udp_rule}
"\$IPTABLES_BIN" -t nat -A PREROUTING -p tcp -d $iran_ip --dport $iran_port -j DNAT --to-destination $eu_ip:$eu_port
"\$IPTABLES_BIN" -t nat -A PREROUTING -p udp -d $iran_ip --dport $iran_port -j DNAT --to-destination $eu_ip:$eu_port
"\$IPTABLES_BIN" -t nat -A POSTROUTING -p tcp -d $eu_ip --dport $eu_port -j MASQUERADE
"\$IPTABLES_BIN" -t nat -A POSTROUTING -p udp -d $eu_ip --dport $eu_port -j MASQUERADE
"\$IPTABLES_BIN" -A FORWARD -p tcp -d $eu_ip --dport $eu_port -j ACCEPT
"\$IPTABLES_BIN" -A FORWARD -p udp -d $eu_ip --dport $eu_port -j ACCEPT
"\$IPTABLES_BIN" -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
EOF

    run_with_sudo chmod 700 "$script_path"
    echo "$script_path"
}

# ------------------------------------------------------------
# STEP 1: CREATE USERS
# ------------------------------------------------------------
add_users() {
    info "Adding system users..."
    local home_dir=""
    for u in "${USERS[@]}"; do
        if id "$u" &>/dev/null; then
            echo "  $u : already exists"
        else
            run_with_sudo useradd -m -s /bin/bash "$u"
            echo "$u:$u" | run_with_sudo chpasswd
            home_dir="/home/$u"
            if [[ "$home_dir" == /home/* && -d "$home_dir" ]]; then
                run_with_sudo rm -rf -- "$home_dir"
                echo "  $u : removed home directory '$home_dir'"
            fi
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
# STEP X: SSH TUNNEL DNAT (INTERACTIVE)
# ------------------------------------------------------------
run_sshtunnel() {
    local iran_port=""
    local iran_host=""
    local iran_ip=""
    local eu_host=""
    local eu_ip=""
    local eu_port=""
    local ssh_client_ip=""
    local blacklist_host=""
    local blacklist_ip=""
    local reboot_script=""
    local cron_line=""
    local value=""

    show_sshtunnel_banner
    info "SSH tunnel DNAT setup (step-by-step)."
    warn "This will flush current iptables rules before adding tunnel rules."
    info "No command is executed until final confirmation."

    info "Step 1/6: Detect current server public IP (Iran side)."
    detect_public_ipv4 || true
    if [[ -n "$DETECTED_IRAN_IP" ]]; then
        info "Detected current server IP: $DETECTED_IRAN_IP (source: $DETECTED_IRAN_IP_SOURCE)"
        if prompt_yes_no "Use this as Iran public IP?" "y"; then
            iran_ip="$DETECTED_IRAN_IP"
        fi
    else
        warn "Could not auto-detect current server public IP."
    fi

    while [[ -z "$iran_ip" ]]; do
        read -r -p "$(printf '\033[1;36m%s\033[0m: ' "Iran public IP/domain (required)")" iran_host
        if [[ -z "$iran_host" ]]; then
            warn "Iran public IP/domain is required."
            continue
        fi
        if iran_ip="$(resolve_ipv4 "$iran_host")"; then
            break
        fi
        warn "Could not resolve '$iran_host' to IPv4. Enter a valid IP/domain."
    done

    info "Step 2/6: Detect current SSH port on this server."
    detect_current_ssh_port || true
    if [[ -n "$DETECTED_SSH_PORT" ]]; then
        info "Detected SSH port: $DETECTED_SSH_PORT (source: $DETECTED_SSH_PORT_SOURCE)"
        if prompt_yes_no "Use this as Iran incoming port?" "y"; then
            iran_port="$DETECTED_SSH_PORT"
        fi
    else
        warn "Could not auto-detect SSH port."
    fi

    while [[ -z "$iran_port" ]]; do
        read -r -p "$(printf '\033[1;36m%s\033[0m: ' "Iran incoming SSH port on this server (required)")" value
        if ! is_valid_port "$value"; then
            warn "Invalid port. Enter a number between 1 and 65535."
            continue
        fi
        iran_port="$value"
    done

    info "Step 3/6: Enter EU server public IP/domain."
    while true; do
        eu_host="$(prompt_with_default "EU server IP/domain" "91.107.247.144")"
        if eu_ip="$(resolve_ipv4 "$eu_host")"; then
            break
        fi
        warn "Could not resolve '$eu_host' to IPv4. Enter a valid IP/domain."
    done

    info "Step 4/6: Enter EU server SSH port."
    while true; do
        eu_port="$(prompt_with_default "EU server SSH port" "$SSH_PORT")"
        if is_valid_port "$eu_port"; then
            break
        fi
        warn "Invalid port. Please enter a number between 1 and 65535."
    done

    info "Step 5/6: Optional bypass IP (will skip DNAT)."
    if prompt_yes_no "Add bypass IP?" "y"; then
        ssh_client_ip="${SSH_CLIENT:-${SSH_CONNECTION:-}}"
        ssh_client_ip="${ssh_client_ip%% *}"

        while true; do
            if [[ -n "$ssh_client_ip" ]]; then
                blacklist_host="$(prompt_with_default "Bypass IP/domain" "$ssh_client_ip")"
            else
                read -r -p "$(printf '\033[1;36m%s\033[0m: ' "Bypass IP/domain (required)")" blacklist_host
                if [[ -z "$blacklist_host" ]]; then
                    warn "Bypass IP/domain is required."
                    continue
                fi
            fi

            if blacklist_ip="$(resolve_ipv4 "$blacklist_host")"; then
                break
            fi
            warn "Could not resolve '$blacklist_host' to IPv4. Enter a valid IP/domain."
        done
    fi

    info "Step 6/6: Review configuration."
    echo "  Iran side : $iran_ip:$iran_port"
    echo "  EU side   : $eu_ip:$eu_port"
    echo "  Bypass IP : ${blacklist_ip:-none}"
    show_sshtunnel_commands "$iran_ip" "$iran_port" "$eu_ip" "$eu_port" "$blacklist_ip"

    if ! prompt_yes_no "Run these commands now?" "y"; then
        warn "SSH tunnel setup cancelled by user."
        return 0
    fi

    info "Applying forwarding: $iran_ip:$iran_port -> $eu_ip:$eu_port"
    run_with_sudo sysctl -w net.ipv4.ip_forward=1
    run_with_sudo iptables -F
    run_with_sudo iptables -t nat -F
    run_with_sudo iptables -X

    if [[ -n "$blacklist_ip" ]]; then
        run_with_sudo iptables -t nat -I PREROUTING 1 -s "$blacklist_ip" -p tcp --dport "$iran_port" -j RETURN
        run_with_sudo iptables -t nat -I PREROUTING 1 -s "$blacklist_ip" -p udp --dport "$iran_port" -j RETURN
        info "Bypass enabled for $blacklist_ip on incoming port $iran_port (TCP+UDP)."
    fi

    run_with_sudo iptables -t nat -A PREROUTING -p tcp -d "$iran_ip" --dport "$iran_port" -j DNAT --to-destination "$eu_ip:$eu_port"
    run_with_sudo iptables -t nat -A PREROUTING -p udp -d "$iran_ip" --dport "$iran_port" -j DNAT --to-destination "$eu_ip:$eu_port"
    run_with_sudo iptables -t nat -A POSTROUTING -p tcp -d "$eu_ip" --dport "$eu_port" -j MASQUERADE
    run_with_sudo iptables -t nat -A POSTROUTING -p udp -d "$eu_ip" --dport "$eu_port" -j MASQUERADE
    run_with_sudo iptables -A FORWARD -p tcp -d "$eu_ip" --dport "$eu_port" -j ACCEPT
    run_with_sudo iptables -A FORWARD -p udp -d "$eu_ip" --dport "$eu_port" -j ACCEPT
    run_with_sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    success "SSH tunnel rules applied."

    if prompt_yes_no "Enable this on reboot (iptables-persistent + cron)?" "n"; then
        info "Installing persistence packages..."
        run_with_sudo apt-get update -y
        run_with_sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
        run_with_sudo netfilter-persistent save
        echo "net.ipv4.ip_forward=1" | run_with_sudo tee /etc/sysctl.d/99-sshtunnel-ipforward.conf >/dev/null

        reboot_script="$(write_sshtunnel_reboot_script "$iran_ip" "$iran_port" "$eu_ip" "$eu_port" "$blacklist_ip")"
        cron_line="@reboot $reboot_script >/var/log/sshtunnel-restore.log 2>&1"

        if command -v crontab &>/dev/null; then
            ensure_root_cron_job "$cron_line"
        else
            warn "crontab not found. Reboot script created at $reboot_script but cron entry was skipped."
        fi

        success "Reboot persistence enabled."
    else
        info "Reboot persistence skipped."
    fi
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
Usage: $0 {users|ssh|recaptcha|udgpw|bbr|sshtunnel|all} [port] [users_list]

  users      - Create users from list (comma-separated)
  ssh        - Change SSH port (default $SSH_PORT) and set ciphers
  recaptcha  - Run install_kernel.sh (reCAPTCHA step)
  udgpw      - Set UDPGW port to $UDPGW_PORT (silent, auto‑correct)
  bbr        - Enable BBR (install_kernel.sh second pass)
  sshtunnel  - Interactive SSH DNAT tunnel + optional reboot persistence
  all        - Execute all steps in the correct order (requires users list)

Example:
  $0 users shayan,anothername
  $0 ssh 2233
  $0 sshtunnel
  $0 all 2233 shayan,anothername
  $0 all shayan,anothername
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
    sshtunnel)  run_sshtunnel ;;
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
