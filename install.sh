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

# ASCIIPLEASE_EDIT_THIS_LINE_CORE: Customize core command ASCII arts in this function.
show_core_action_ascii() {
    local action="${1:-main}"
    echo -e "\033[1;32m"
    case "$action" in
        users)
            cat <<'EOF'
 █████  █████  █████████  ██████████ ███████████    █████████ 
▒▒███  ▒▒███  ███▒▒▒▒▒███▒▒███▒▒▒▒▒█▒▒███▒▒▒▒▒███  ███▒▒▒▒▒███
 ▒███   ▒███ ▒███    ▒▒▒  ▒███  █ ▒  ▒███    ▒███ ▒███    ▒▒▒ 
 ▒███   ▒███ ▒▒█████████  ▒██████    ▒██████████  ▒▒█████████ 
 ▒███   ▒███  ▒▒▒▒▒▒▒▒███ ▒███▒▒█    ▒███▒▒▒▒▒███  ▒▒▒▒▒▒▒▒███
 ▒███   ▒███  ███    ▒███ ▒███ ▒   █ ▒███    ▒███  ███    ▒███
 ▒▒████████  ▒▒█████████  ██████████ █████   █████▒▒█████████ 
  ▒▒▒▒▒▒▒▒    ▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒▒▒▒▒▒ ▒▒▒▒▒   ▒▒▒▒▒  ▒▒▒▒▒▒▒▒▒  
                                                              
                                                              
                                                              
EOF
            ;;
        ssh)
            cat <<'EOF'
  █████████   █████████  █████   █████
 ███▒▒▒▒▒███ ███▒▒▒▒▒███▒▒███   ▒▒███ 
▒███    ▒▒▒ ▒███    ▒▒▒  ▒███    ▒███ 
▒▒█████████ ▒▒█████████  ▒███████████ 
 ▒▒▒▒▒▒▒▒███ ▒▒▒▒▒▒▒▒███ ▒███▒▒▒▒▒███ 
 ███    ▒███ ███    ▒███ ▒███    ▒███ 
▒▒█████████ ▒▒█████████  █████   █████
 ▒▒▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒   ▒▒▒▒▒ 
                                      
                                      
                                      
EOF
            ;;
        recaptcha)
            cat <<'EOF'
 ███████████   ██████████   █████████    █████████   ███████████  ███████████   █████████  █████   █████   █████████  
▒▒███▒▒▒▒▒███ ▒▒███▒▒▒▒▒█  ███▒▒▒▒▒███  ███▒▒▒▒▒███ ▒▒███▒▒▒▒▒███▒█▒▒▒███▒▒▒█  ███▒▒▒▒▒███▒▒███   ▒▒███   ███▒▒▒▒▒███ 
 ▒███    ▒███  ▒███  █ ▒  ███     ▒▒▒  ▒███    ▒███  ▒███    ▒███▒   ▒███  ▒  ███     ▒▒▒  ▒███    ▒███  ▒███    ▒███ 
 ▒██████████   ▒██████   ▒███          ▒███████████  ▒██████████     ▒███    ▒███          ▒███████████  ▒███████████ 
 ▒███▒▒▒▒▒███  ▒███▒▒█   ▒███          ▒███▒▒▒▒▒███  ▒███▒▒▒▒▒▒      ▒███    ▒███          ▒███▒▒▒▒▒███  ▒███▒▒▒▒▒███ 
 ▒███    ▒███  ▒███ ▒   █▒▒███     ███ ▒███    ▒███  ▒███            ▒███    ▒▒███     ███ ▒███    ▒███  ▒███    ▒███ 
 █████   █████ ██████████ ▒▒█████████  █████   █████ █████           █████    ▒▒█████████  █████   █████ █████   █████
▒▒▒▒▒   ▒▒▒▒▒ ▒▒▒▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒   ▒▒▒▒▒ ▒▒▒▒▒           ▒▒▒▒▒      ▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒   ▒▒▒▒▒ ▒▒▒▒▒   ▒▒▒▒▒ 
                                                                                                                      
                                                                                                                      
                                                                                                                      
EOF
            ;;
        udgpw)
            cat <<'EOF'
 █████  █████ ██████████     █████████  ███████████  █████   ███   █████
▒▒███  ▒▒███ ▒▒███▒▒▒▒███   ███▒▒▒▒▒███▒▒███▒▒▒▒▒███▒▒███   ▒███  ▒▒███ 
 ▒███   ▒███  ▒███   ▒▒███ ███     ▒▒▒  ▒███    ▒███ ▒███   ▒███   ▒███ 
 ▒███   ▒███  ▒███    ▒███▒███          ▒██████████  ▒███   ▒███   ▒███ 
 ▒███   ▒███  ▒███    ▒███▒███    █████ ▒███▒▒▒▒▒▒   ▒▒███  █████  ███  
 ▒███   ▒███  ▒███    ███ ▒▒███  ▒▒███  ▒███          ▒▒▒█████▒█████▒   
 ▒▒████████   ██████████   ▒▒█████████  █████           ▒▒███ ▒▒███     
  ▒▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒▒▒     ▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒             ▒▒▒   ▒▒▒      
                                                                        
                                                                        
                                                                        
EOF
            ;;
        bbr)
            cat <<'EOF'
 ███████████  ███████████  ███████████  
▒▒███▒▒▒▒▒███▒▒███▒▒▒▒▒███▒▒███▒▒▒▒▒███ 
 ▒███    ▒███ ▒███    ▒███ ▒███    ▒███ 
 ▒██████████  ▒██████████  ▒██████████  
 ▒███▒▒▒▒▒███ ▒███▒▒▒▒▒███ ▒███▒▒▒▒▒███ 
 ▒███    ▒███ ▒███    ▒███ ▒███    ▒███ 
 ███████████  ███████████  █████   █████
▒▒▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒   ▒▒▒▒▒ 
                                        
                                        
                                        
EOF
            ;;
        all)
            cat <<'EOF'
   █████████   █████       █████          ███████████  ███████████      ███████      █████████  ██████████  █████████   █████████ 
  ███▒▒▒▒▒███ ▒▒███       ▒▒███          ▒▒███▒▒▒▒▒███▒▒███▒▒▒▒▒███   ███▒▒▒▒▒███   ███▒▒▒▒▒███▒▒███▒▒▒▒▒█ ███▒▒▒▒▒███ ███▒▒▒▒▒███
 ▒███    ▒███  ▒███        ▒███           ▒███    ▒███ ▒███    ▒███  ███     ▒▒███ ███     ▒▒▒  ▒███  █ ▒ ▒███    ▒▒▒ ▒███    ▒▒▒ 
 ▒███████████  ▒███        ▒███           ▒██████████  ▒██████████  ▒███      ▒███▒███          ▒██████   ▒▒█████████ ▒▒█████████ 
 ▒███▒▒▒▒▒███  ▒███        ▒███           ▒███▒▒▒▒▒▒   ▒███▒▒▒▒▒███ ▒███      ▒███▒███          ▒███▒▒█    ▒▒▒▒▒▒▒▒███ ▒▒▒▒▒▒▒▒███
 ▒███    ▒███  ▒███      █ ▒███      █    ▒███         ▒███    ▒███ ▒▒███     ███ ▒▒███     ███ ▒███ ▒   █ ███    ▒███ ███    ▒███
 █████   █████ ███████████ ███████████    █████        █████   █████ ▒▒▒███████▒   ▒▒█████████  ██████████▒▒█████████ ▒▒█████████ 
▒▒▒▒▒   ▒▒▒▒▒ ▒▒▒▒▒▒▒▒▒▒▒ ▒▒▒▒▒▒▒▒▒▒▒    ▒▒▒▒▒        ▒▒▒▒▒   ▒▒▒▒▒    ▒▒▒▒▒▒▒      ▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒▒  
                                                                                                                                  
                                                                                                                                  
                                                                                                                                  
EOF
            ;;
        *)
            cat <<'EOF'
  █████████  █████   █████   █████████   █████ █████   █████████   ██████   █████
 ███▒▒▒▒▒███▒▒███   ▒▒███   ███▒▒▒▒▒███ ▒▒███ ▒▒███   ███▒▒▒▒▒███ ▒▒██████ ▒▒███ 
▒███    ▒▒▒  ▒███    ▒███  ▒███    ▒███  ▒▒███ ███   ▒███    ▒███  ▒███▒███ ▒███ 
▒▒█████████  ▒███████████  ▒███████████   ▒▒█████    ▒███████████  ▒███▒▒███▒███ 
 ▒▒▒▒▒▒▒▒███ ▒███▒▒▒▒▒███  ▒███▒▒▒▒▒███    ▒▒███     ▒███▒▒▒▒▒███  ▒███ ▒▒██████ 
 ███    ▒███ ▒███    ▒███  ▒███    ▒███     ▒███     ▒███    ▒███  ▒███  ▒▒█████ 
▒▒█████████  █████   █████ █████   █████    █████    █████   █████ █████  ▒▒█████
 ▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒   ▒▒▒▒▒ ▒▒▒▒▒   ▒▒▒▒▒    ▒▒▒▒▒    ▒▒▒▒▒   ▒▒▒▒▒ ▒▒▒▒▒    ▒▒▒▒▒ 
                                                                                 
                                                                                 
                                                                                 
EOF
            ;;
    esac
    echo -e "\033[0m"
}

show_sshtunnel_banner() {
    echo -e "\033[1;35m"
    cat <<'EOF'

  █████████   █████████  █████   █████    ███████████ █████  █████ ██████   █████ ██████   █████ ██████████ █████  
 ███░░░░░███ ███░░░░░███░░███   ░░███    ░█░░░███░░░█░░███  ░░███ ░░██████ ░░███ ░░██████ ░░███ ░░███░░░░░█░░███   
░███    ░░░ ░███    ░░░  ░███    ░███    ░   ░███  ░  ░███   ░███  ░███░███ ░███  ░███░███ ░███  ░███  █ ░  ░███   
░░█████████ ░░█████████  ░███████████        ░███     ░███   ░███  ░███░░███░███  ░███░░███░███  ░██████    ░███   
 ░░░░░░░░███ ░░░░░░░░███ ░███░░░░░███        ░███     ░███   ░███  ░███ ░░██████  ░███ ░░██████  ░███░░█    ░███  
 ███    ░███ ███    ░███ ░███    ░███        ░███     ░███   ░███  ░███  ░░█████  ░███  ░░█████  ░███ ░   █ ░███      █
░░█████████ ░░█████████  █████   █████       █████    ░░████████   █████  ░░█████ █████  ░░█████ ██████████ ███████████
 ░░░░░░░░░   ░░░░░░░░░  ░░░░░   ░░░░░       ░░░░░      ░░░░░░░░   ░░░░░    ░░░░░ ░░░░░    ░░░░░ ░░░░░░░░░░ ░░░░░░░░░░░                                                                                                           
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
    echo "Commands that will run on current server:"
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
    show_core_action_ascii "users"
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
    show_core_action_ascii "ssh"
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
    show_core_action_ascii "recaptcha"
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
    show_core_action_ascii "udgpw"
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
    show_core_action_ascii "bbr"
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
    local enable_reboot_persistence="n"

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
        read -r -p "$(printf '\033[1;36m%s\033[0m: ' "EU server IP/domain (required)")" eu_host
        if [[ -z "$eu_host" ]]; then
            warn "EU server IP/domain is required."
            continue
        fi
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
    echo "  Current server (Iran): $iran_ip:$iran_port"
    echo "  Destination (EU)     : $eu_ip:$eu_port"
    echo "  Bypass source IP     : ${blacklist_ip:-none}"
    show_sshtunnel_commands "$iran_ip" "$iran_port" "$eu_ip" "$eu_port" "$blacklist_ip"

    if prompt_yes_no "Also enable these rules on reboot (iptables-persistent + cron)?" "n"; then
        enable_reboot_persistence="y"
    fi

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

    if [[ "$enable_reboot_persistence" == "y" ]]; then
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
# STEP M: USER TRAFFIC MONITOR PANEL (INTERACTIVE + TMUX)
# ------------------------------------------------------------
show_monitor_banner() {
    echo -e "\033[1;35m"
    cat <<'EOF'

 ██████   ██████    ███████    ██████   █████ █████ ███████████    ███████    ███████████  
▒▒██████ ██████   ███▒▒▒▒▒███ ▒▒██████ ▒▒███ ▒▒███ ▒█▒▒▒███▒▒▒█  ███▒▒▒▒▒███ ▒▒███▒▒▒▒▒███ 
 ▒███▒█████▒███  ███     ▒▒███ ▒███▒███ ▒███  ▒███ ▒   ▒███  ▒  ███     ▒▒███ ▒███    ▒███ 
 ▒███▒▒███ ▒███ ▒███      ▒███ ▒███▒▒███▒███  ▒███     ▒███    ▒███      ▒███ ▒██████████  
 ▒███ ▒▒▒  ▒███ ▒███      ▒███ ▒███ ▒▒██████  ▒███     ▒███    ▒███      ▒███ ▒███▒▒▒▒▒███ 
 ▒███      ▒███ ▒▒███     ███  ▒███  ▒▒█████  ▒███     ▒███    ▒▒███     ███  ▒███    ▒███ 
 █████     █████ ▒▒▒███████▒   █████  ▒▒█████ █████    █████    ▒▒▒███████▒   █████   █████
▒▒▒▒▒     ▒▒▒▒▒    ▒▒▒▒▒▒▒    ▒▒▒▒▒    ▒▒▒▒▒ ▒▒▒▒▒    ▒▒▒▒▒       ▒▒▒▒▒▒▒    ▒▒▒▒▒   ▒▒▒▒▒ 
                                                                                           
EOF
    echo -e "\033[0m"
}

# ASCIIPLEASE_EDIT_THIS_LINE: Customize monitor ASCII arts in this function.
monitor_show_action_ascii() {
    local action="${1:-menu}"
    echo -e "\033[1;36m"
    case "$action" in
        install)
            cat <<'EOF'
 █████ ██████   █████  █████████  ███████████   █████████   █████       █████      
▒▒███ ▒▒██████ ▒▒███  ███▒▒▒▒▒███▒█▒▒▒███▒▒▒█  ███▒▒▒▒▒███ ▒▒███       ▒▒███       
 ▒███  ▒███▒███ ▒███ ▒███    ▒▒▒ ▒   ▒███  ▒  ▒███    ▒███  ▒███        ▒███       
 ▒███  ▒███▒▒███▒███ ▒▒█████████     ▒███     ▒███████████  ▒███        ▒███       
 ▒███  ▒███ ▒▒██████  ▒▒▒▒▒▒▒▒███    ▒███     ▒███▒▒▒▒▒███  ▒███        ▒███       
 ▒███  ▒███  ▒▒█████  ███    ▒███    ▒███     ▒███    ▒███  ▒███      █ ▒███      █
 █████ █████  ▒▒█████▒▒█████████     █████    █████   █████ ███████████ ███████████
▒▒▒▒▒ ▒▒▒▒▒    ▒▒▒▒▒  ▒▒▒▒▒▒▒▒▒     ▒▒▒▒▒    ▒▒▒▒▒   ▒▒▒▒▒ ▒▒▒▒▒▒▒▒▒▒▒ ▒▒▒▒▒▒▒▒▒▒▒ 
                                                                                   
                                                                                   
                                                                                   
EOF
            ;;
        edit)
            cat <<'EOF'
 ██████████ ██████████   █████ ███████████
▒▒███▒▒▒▒▒█▒▒███▒▒▒▒███ ▒▒███ ▒█▒▒▒███▒▒▒█
 ▒███  █ ▒  ▒███   ▒▒███ ▒███ ▒   ▒███  ▒ 
 ▒██████    ▒███    ▒███ ▒███     ▒███    
 ▒███▒▒█    ▒███    ▒███ ▒███     ▒███    
 ▒███ ▒   █ ▒███    ███  ▒███     ▒███    
 ██████████ ██████████   █████    █████   
▒▒▒▒▒▒▒▒▒▒ ▒▒▒▒▒▒▒▒▒▒   ▒▒▒▒▒    ▒▒▒▒▒    
                                          
                                          
                                          
EOF
            ;;
        restart)
            cat <<'EOF'
 ███████████   ██████████  █████████  ███████████   █████████   ███████████   ███████████
▒▒███▒▒▒▒▒███ ▒▒███▒▒▒▒▒█ ███▒▒▒▒▒███▒█▒▒▒███▒▒▒█  ███▒▒▒▒▒███ ▒▒███▒▒▒▒▒███ ▒█▒▒▒███▒▒▒█
 ▒███    ▒███  ▒███  █ ▒ ▒███    ▒▒▒ ▒   ▒███  ▒  ▒███    ▒███  ▒███    ▒███ ▒   ▒███  ▒ 
 ▒██████████   ▒██████   ▒▒█████████     ▒███     ▒███████████  ▒██████████      ▒███    
 ▒███▒▒▒▒▒███  ▒███▒▒█    ▒▒▒▒▒▒▒▒███    ▒███     ▒███▒▒▒▒▒███  ▒███▒▒▒▒▒███     ▒███    
 ▒███    ▒███  ▒███ ▒   █ ███    ▒███    ▒███     ▒███    ▒███  ▒███    ▒███     ▒███    
 █████   █████ ██████████▒▒█████████     █████    █████   █████ █████   █████    █████   
▒▒▒▒▒   ▒▒▒▒▒ ▒▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒▒▒▒▒     ▒▒▒▒▒    ▒▒▒▒▒   ▒▒▒▒▒ ▒▒▒▒▒   ▒▒▒▒▒    ▒▒▒▒▒    
                                                                                         
                                                                                         
                                                                                         
EOF
            ;;
        status)
            cat <<'EOF'
  █████████  ███████████   █████████   ███████████ █████  █████  █████████ 
 ███▒▒▒▒▒███▒█▒▒▒███▒▒▒█  ███▒▒▒▒▒███ ▒█▒▒▒███▒▒▒█▒▒███  ▒▒███  ███▒▒▒▒▒███
▒███    ▒▒▒ ▒   ▒███  ▒  ▒███    ▒███ ▒   ▒███  ▒  ▒███   ▒███ ▒███    ▒▒▒ 
▒▒█████████     ▒███     ▒███████████     ▒███     ▒███   ▒███ ▒▒█████████ 
 ▒▒▒▒▒▒▒▒███    ▒███     ▒███▒▒▒▒▒███     ▒███     ▒███   ▒███  ▒▒▒▒▒▒▒▒███
 ███    ▒███    ▒███     ▒███    ▒███     ▒███     ▒███   ▒███  ███    ▒███
▒▒█████████     █████    █████   █████    █████    ▒▒████████  ▒▒█████████ 
 ▒▒▒▒▒▒▒▒▒     ▒▒▒▒▒    ▒▒▒▒▒   ▒▒▒▒▒    ▒▒▒▒▒      ▒▒▒▒▒▒▒▒    ▒▒▒▒▒▒▒▒▒  
                                                                           
                                                                           
                                                                           
EOF
            ;;
        logs)
            cat <<'EOF'
 █████          ███████      █████████   █████████ 
▒▒███         ███▒▒▒▒▒███   ███▒▒▒▒▒███ ███▒▒▒▒▒███
 ▒███        ███     ▒▒███ ███     ▒▒▒ ▒███    ▒▒▒ 
 ▒███       ▒███      ▒███▒███         ▒▒█████████ 
 ▒███       ▒███      ▒███▒███    █████ ▒▒▒▒▒▒▒▒███
 ▒███      █▒▒███     ███ ▒▒███  ▒▒███  ███    ▒███
 ███████████ ▒▒▒███████▒   ▒▒█████████ ▒▒█████████ 
▒▒▒▒▒▒▒▒▒▒▒    ▒▒▒▒▒▒▒      ▒▒▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒▒  
                                                   
                                                   
                                                   
EOF
            ;;
        commands)
            cat <<'EOF'
   █████████     ███████    ██████   ██████ ██████   ██████   █████████   ██████   █████ ██████████    █████████ 
  ███▒▒▒▒▒███  ███▒▒▒▒▒███ ▒▒██████ ██████ ▒▒██████ ██████   ███▒▒▒▒▒███ ▒▒██████ ▒▒███ ▒▒███▒▒▒▒███  ███▒▒▒▒▒███
 ███     ▒▒▒  ███     ▒▒███ ▒███▒█████▒███  ▒███▒█████▒███  ▒███    ▒███  ▒███▒███ ▒███  ▒███   ▒▒███▒███    ▒▒▒ 
▒███         ▒███      ▒███ ▒███▒▒███ ▒███  ▒███▒▒███ ▒███  ▒███████████  ▒███▒▒███▒███  ▒███    ▒███▒▒█████████ 
▒███         ▒███      ▒███ ▒███ ▒▒▒  ▒███  ▒███ ▒▒▒  ▒███  ▒███▒▒▒▒▒███  ▒███ ▒▒██████  ▒███    ▒███ ▒▒▒▒▒▒▒▒███
▒▒███     ███▒▒███     ███  ▒███      ▒███  ▒███      ▒███  ▒███    ▒███  ▒███  ▒▒█████  ▒███    ███  ███    ▒███
 ▒▒█████████  ▒▒▒███████▒   █████     █████ █████     █████ █████   █████ █████  ▒▒█████ ██████████  ▒▒█████████ 
  ▒▒▒▒▒▒▒▒▒     ▒▒▒▒▒▒▒    ▒▒▒▒▒     ▒▒▒▒▒ ▒▒▒▒▒     ▒▒▒▒▒ ▒▒▒▒▒   ▒▒▒▒▒ ▒▒▒▒▒    ▒▒▒▒▒ ▒▒▒▒▒▒▒▒▒▒    ▒▒▒▒▒▒▒▒▒  
                                                                                                                 
                                                                                                                 
                                                                                                                 
EOF
            ;;
        *)
            cat <<'EOF'

 ██████   ██████    ███████    ██████   █████ █████ ███████████    ███████    ███████████  
▒▒██████ ██████   ███▒▒▒▒▒███ ▒▒██████ ▒▒███ ▒▒███ ▒█▒▒▒███▒▒▒█  ███▒▒▒▒▒███ ▒▒███▒▒▒▒▒███ 
 ▒███▒█████▒███  ███     ▒▒███ ▒███▒███ ▒███  ▒███ ▒   ▒███  ▒  ███     ▒▒███ ▒███    ▒███ 
 ▒███▒▒███ ▒███ ▒███      ▒███ ▒███▒▒███▒███  ▒███     ▒███    ▒███      ▒███ ▒██████████  
 ▒███ ▒▒▒  ▒███ ▒███      ▒███ ▒███ ▒▒██████  ▒███     ▒███    ▒███      ▒███ ▒███▒▒▒▒▒███ 
 ▒███      ▒███ ▒▒███     ███  ▒███  ▒▒█████  ▒███     ▒███    ▒▒███     ███  ▒███    ▒███ 
 █████     █████ ▒▒▒███████▒   █████  ▒▒█████ █████    █████    ▒▒▒███████▒   █████   █████
▒▒▒▒▒     ▒▒▒▒▒    ▒▒▒▒▒▒▒    ▒▒▒▒▒    ▒▒▒▒▒ ▒▒▒▒▒    ▒▒▒▒▒       ▒▒▒▒▒▒▒    ▒▒▒▒▒   ▒▒▒▒▒ 
    
EOF
            ;;
    esac
    echo -e "\033[0m"
}

monitor_random_port() {
    local p=""
    if command -v shuf &>/dev/null; then
        p="$(shuf -i 1024-65535 -n 1)"
    else
        p="$(( (((RANDOM << 15) | RANDOM) % (65535 - 1024 + 1)) + 1024 ))"
    fi
    echo "$p"
}

monitor_show_runtime_commands() {
    local monitor_home="/home/monitor"
    local start_cmd="cd $monitor_home && $monitor_home/venv/bin/python3 $monitor_home/monitor_panel.py >> $monitor_home/monitor.log 2>&1"
    local tmux_bin
    tmux_bin="$(command -v tmux || echo /usr/bin/tmux)"

    monitor_show_action_ascii "commands"
    echo "============================================================"
    echo "                 MONITOR RUNTIME COMMANDS"
    echo "============================================================"
    echo "Start/Restart:"
    echo "  sudo $tmux_bin kill-session -t monitor-panel"
    echo "  sudo $tmux_bin new-session -d -s monitor-panel \"$start_cmd\""
    echo
    echo "Attach to running tmux session:"
    echo "  sudo $tmux_bin attach -t monitor-panel"
    echo
    echo "Live logs (quit with q in menu option 5):"
    echo "  sudo tail -n 80 -f $monitor_home/monitor.log"
    echo "============================================================"
}

monitor_config_get() {
    local file="$1"
    local key="$2"
    run_with_sudo awk -F= -v k="$key" '$1==k {print substr($0, length(k)+2); exit}' "$file" 2>/dev/null || true
}

monitor_detect_public_host() {
    local fallback=""
    detect_public_ipv4 || true
    if [[ -n "${DETECTED_IRAN_IP:-}" ]]; then
        echo "$DETECTED_IRAN_IP"
        return 0
    fi
    fallback="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    echo "${fallback:-127.0.0.1}"
}

monitor_write_config_file() {
    local config_file="$1"
    local panel_user="$2"
    local panel_pass="$3"
    local panel_bind="$4"
    local panel_port="$5"
    local public_host="$6"
    local public_scheme="$7"

    panel_user="${panel_user//$'\n'/}"
    panel_user="${panel_user//$'\r'/}"
    panel_pass="${panel_pass//$'\n'/}"
    panel_pass="${panel_pass//$'\r'/}"
    panel_bind="${panel_bind//$'\n'/}"
    panel_bind="${panel_bind//$'\r'/}"
    panel_port="${panel_port//$'\n'/}"
    panel_port="${panel_port//$'\r'/}"
    public_host="${public_host//$'\n'/}"
    public_host="${public_host//$'\r'/}"
    public_scheme="${public_scheme//$'\n'/}"
    public_scheme="${public_scheme//$'\r'/}"

    run_with_sudo tee "$config_file" >/dev/null <<EOF
PANEL_USER=$panel_user
PANEL_PASS=$panel_pass
PANEL_BIND=$panel_bind
PANEL_PORT=$panel_port
PANEL_PUBLIC_HOST=$public_host
PANEL_SCHEME=$public_scheme
EOF

    run_with_sudo chmod 600 "$config_file"
}

monitor_write_python_script() {
    local monitor_script="$1"

    run_with_sudo tee "$monitor_script" >/dev/null <<'PYEOF'
#!/usr/bin/env python3
import logging
import os
import pwd
import random
import re
import subprocess
import sys
import time
from functools import wraps

from flask import Flask, Response, jsonify, render_template_string, request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.env")
USERS_CMD = r"""awk -F: '$3>=1000 && $7 !~ /(nologin|false)$/ && $1!="ubuntu" {print $1":"$3}' /etc/passwd | sort -t: -k2,2nr | cut -d: -f1"""
CHAIN_NAME = "MONITOR_USAGE"
LAST_RULE_SYNC = 0.0


def load_config():
    random_port = str(random.randint(1024, 65535))
    cfg = {
        "PANEL_USER": "admin",
        "PANEL_PASS": "change-me",
        "PANEL_BIND": "0.0.0.0",
        "PANEL_PORT": random_port,
        "PANEL_PUBLIC_HOST": "127.0.0.1",
        "PANEL_SCHEME": "http",
    }
    if os.path.isfile(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    try:
        loaded_port = int(cfg.get("PANEL_PORT", random_port))
        if loaded_port < 1024 or loaded_port > 65535:
            raise ValueError("port_out_of_range")
        cfg["PANEL_PORT"] = str(loaded_port)
    except ValueError:
        cfg["PANEL_PORT"] = random_port
    return cfg


CFG = load_config()
app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("monitor")


def run_cmd(args, quiet=False):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0 and not quiet:
        err_text = (result.stderr or result.stdout or "").strip()
        log.warning("Command failed: %s | rc=%s | out=%s", " ".join(args), result.returncode, err_text)
    return result


def list_target_users():
    result = subprocess.run(["bash", "-lc", USERS_CMD], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        log.warning("User list command failed: %s", (result.stderr or "").strip())
        return []
    users = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    log.info("Detected %d eligible users", len(users))
    return users


def ensure_iptables_rules(users):
    global LAST_RULE_SYNC
    now = time.time()
    if now - LAST_RULE_SYNC < 10:
        return

    run_cmd(["iptables", "-w", "-N", CHAIN_NAME], quiet=True)
    hook_check = run_cmd(["iptables", "-w", "-C", "OUTPUT", "-j", CHAIN_NAME], quiet=True)
    if hook_check.returncode != 0:
        run_cmd(["iptables", "-w", "-I", "OUTPUT", "1", "-j", CHAIN_NAME])
        log.info("Attached %s chain to OUTPUT", CHAIN_NAME)

    for user in users:
        try:
            uid = pwd.getpwnam(user).pw_uid
        except KeyError:
            continue
        comment = f"MONITOR:{user}"
        check = run_cmd(
            [
                "iptables",
                "-w",
                "-C",
                CHAIN_NAME,
                "-m",
                "owner",
                "--uid-owner",
                str(uid),
                "-m",
                "comment",
                "--comment",
                comment,
                "-j",
                "RETURN",
            ],
            quiet=True,
        )
        if check.returncode != 0:
            run_cmd(
                [
                    "iptables",
                    "-w",
                    "-A",
                    CHAIN_NAME,
                    "-m",
                    "owner",
                    "--uid-owner",
                    str(uid),
                    "-m",
                    "comment",
                    "--comment",
                    comment,
                    "-j",
                    "RETURN",
                ]
            )
            log.info("Added counter rule for user=%s uid=%s", user, uid)

    LAST_RULE_SYNC = now


def read_usage_counters():
    result = run_cmd(["iptables", "-w", "-nvx", "-L", CHAIN_NAME], quiet=True)
    if result.returncode != 0:
        log.warning("Unable to read iptables counters for chain=%s", CHAIN_NAME)
        return {}

    usage = {}
    pattern = re.compile(r"^\s*\d+\s+(\d+).*/\*\s*MONITOR:([A-Za-z0-9._-]+)\s*\*/")
    for line in result.stdout.splitlines():
        match = pattern.search(line)
        if not match:
            continue
        bytes_used = int(match.group(1))
        user = match.group(2)
        usage[user] = bytes_used
    return usage


def auth_ok():
    auth = request.authorization
    return bool(auth and auth.username == CFG["PANEL_USER"] and auth.password == CFG["PANEL_PASS"])


def require_auth(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        if not auth_ok():
            return Response("Authentication required", 401, {"WWW-Authenticate": 'Basic realm="Monitor Panel"'})
        return handler(*args, **kwargs)

    return wrapped


HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Monitor Panel</title>
  <style>
    :root {
      --bg-a: #081a1f;
      --bg-b: #12343b;
      --card: rgba(255,255,255,0.08);
      --line: rgba(255,255,255,0.16);
      --text: #e6f4f1;
      --muted: #96b7b1;
      --accent: #26d4a0;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      font-family: "Trebuchet MS", "Segoe UI", sans-serif;
      background: radial-gradient(1000px 600px at 15% 0%, #1f555f 0%, var(--bg-a) 45%, var(--bg-b) 100%);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .wrap {
      width: min(980px, 100%);
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 16px;
      backdrop-filter: blur(8px);
      box-shadow: 0 20px 50px rgba(0,0,0,0.35);
      overflow: hidden;
    }
    .top {
      padding: 18px 20px;
      border-bottom: 1px solid var(--line);
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      flex-wrap: wrap;
    }
    .title {
      font-size: 22px;
      letter-spacing: 0.5px;
      font-weight: 700;
    }
    .meta {
      color: var(--muted);
      font-size: 13px;
    }
    .pulse {
      color: var(--accent);
      font-weight: 600;
      animation: blink 1s infinite;
    }
    @keyframes blink {
      0%,100% { opacity: 1; }
      50% { opacity: .35; }
    }
    table {
      width: 100%;
      border-collapse: collapse;
    }
    th, td {
      padding: 12px 14px;
      text-align: left;
      border-bottom: 1px solid var(--line);
    }
    th {
      color: #bde8df;
      font-size: 12px;
      letter-spacing: .08em;
      text-transform: uppercase;
      background: rgba(0,0,0,0.15);
    }
    td {
      font-size: 14px;
    }
    tr:last-child td { border-bottom: none; }
    .user { font-weight: 700; }
    .muted { color: var(--muted); }
    .empty {
      padding: 28px 20px;
      color: var(--muted);
    }
    .foot {
      padding: 12px 14px 18px;
      color: var(--muted);
      font-size: 12px;
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div>
        <div class="title">Live User Data Usage Panel</div>
        <div class="meta">Refresh: 5x per second | Source: iptables owner UID counters</div>
      </div>
      <div class="meta">Status: <span class="pulse">LIVE</span></div>
    </div>
    <div id="tableWrap">
      <div class="empty">Loading...</div>
    </div>
    <div class="foot">Units auto-switch between KB / MB / GB.</div>
  </div>

  <script>
    const prev = new Map();
    let prevTs = performance.now();

    function unit(bytes) {
      if (bytes < 1024) return bytes.toFixed(0) + " B";
      if (bytes < 1024 ** 2) return (bytes / 1024).toFixed(2) + " KB";
      if (bytes < 1024 ** 3) return (bytes / (1024 ** 2)).toFixed(2) + " MB";
      return (bytes / (1024 ** 3)).toFixed(2) + " GB";
    }

    function render(users) {
      if (!users.length) {
        document.getElementById("tableWrap").innerHTML =
          '<div class="empty">No eligible users found.</div>';
        return;
      }
      const now = performance.now();
      const dt = Math.max((now - prevTs) / 1000, 0.001);
      prevTs = now;

      const rows = users.map((u, idx) => {
        const old = prev.has(u.username) ? prev.get(u.username) : u.bytes;
        const delta = Math.max(u.bytes - old, 0);
        const rate = delta / dt;
        prev.set(u.username, u.bytes);
        return `
          <tr>
            <td>${idx + 1}</td>
            <td class="user">${u.username}</td>
            <td>${unit(u.bytes)}</td>
            <td>${unit(rate)}/s</td>
          </tr>
        `;
      }).join("");

      document.getElementById("tableWrap").innerHTML = `
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>User</th>
              <th>Total Used</th>
              <th>Live Speed</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      `;
    }

    async function tick() {
      try {
        const res = await fetch("/api/data", { cache: "no-store" });
        if (!res.ok) throw new Error("bad response");
        const data = await res.json();
        render(data.users || []);
      } catch (err) {
        document.getElementById("tableWrap").innerHTML =
          '<div class="empty">Panel error: cannot read live data. Check monitor log.</div>';
      }
    }

    tick();
    setInterval(tick, 200);
  </script>
</body>
</html>
"""


@app.get("/")
@require_auth
def home():
    log.info("Serving panel home to %s", request.remote_addr)
    return render_template_string(HTML)


@app.get("/api/data")
@require_auth
def api_data():
    try:
        users = list_target_users()
        ensure_iptables_rules(users)
        usage = read_usage_counters()
        payload = [{"username": user, "bytes": int(usage.get(user, 0))} for user in users]
        return jsonify({"users": payload, "updated_at": int(time.time())})
    except Exception as exc:
        log.exception("api_data failed: %s", exc)
        return jsonify({"users": [], "error": "internal_error", "updated_at": int(time.time())}), 500


@app.get("/health")
def health():
    return jsonify({"ok": True, "ts": int(time.time())})


def main():
    host = CFG.get("PANEL_BIND", "0.0.0.0")
    port = int(CFG.get("PANEL_PORT", str(random.randint(1024, 65535))))
    public_host = CFG.get("PANEL_PUBLIC_HOST", "127.0.0.1")
    scheme = CFG.get("PANEL_SCHEME", "http")
    log.info("Starting monitor panel on %s:%s", host, port)
    log.info("Panel login user=%s", CFG.get("PANEL_USER", "admin"))
    log.info("Public link: %s://%s:%s", scheme, public_host, port)
    log.info("Health URL: %s://%s:%s/health", scheme, public_host, port)
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
PYEOF

    run_with_sudo chmod 755 "$monitor_script"
}

monitor_ensure_reboot_autostart() {
    local monitor_home="$1"
    local tmux_bin=""
    local start_cmd=""
    local cron_line=""
    local current_cron=""

    tmux_bin="$(command -v tmux || echo /usr/bin/tmux)"
    start_cmd="cd $monitor_home && $monitor_home/venv/bin/python3 $monitor_home/monitor_panel.py >> $monitor_home/monitor.log 2>&1"
    cron_line="@reboot $tmux_bin has-session -t monitor-panel 2>/dev/null || $tmux_bin new-session -d -s monitor-panel '$start_cmd'"

    info "Running: crontab -l (check existing reboot entry)"
    current_cron="$(run_with_sudo crontab -l 2>/dev/null || true)"
    if grep -Fqx "$cron_line" <<<"$current_cron"; then
        info "Reboot auto-start entry already exists."
        return 0
    fi

    info "Running: add @reboot monitor-panel tmux command to root crontab"
    {
        [[ -n "$current_cron" ]] && printf '%s\n' "$current_cron"
        printf '%s\n' "$cron_line"
    } | run_with_sudo crontab -
}

monitor_start_tmux() {
    local monitor_home="$1"
    local session_name="monitor-panel"
    local start_cmd="cd $monitor_home && $monitor_home/venv/bin/python3 $monitor_home/monitor_panel.py >> $monitor_home/monitor.log 2>&1"

    info "Running: tmux has-session -t $session_name"
    if run_with_sudo tmux has-session -t "$session_name" 2>/dev/null; then
        info "Running: tmux kill-session -t $session_name"
        run_with_sudo tmux kill-session -t "$session_name"
    fi
    info "Running: tmux new-session -d -s $session_name \"$start_cmd\""
    run_with_sudo tmux new-session -d -s "$session_name" "$start_cmd"
}

monitor_status() {
    local monitor_home="/home/monitor"
    local config_file="$monitor_home/config.env"
    local panel_user=""
    local panel_pass=""
    local panel_port=""
    local public_host=""
    local public_scheme=""

    if [[ ! -f "$config_file" ]]; then
        warn "Monitor is not installed yet. Run: $0 monitor and choose option 1."
        return 1
    fi

    monitor_show_action_ascii "status"
    panel_user="$(monitor_config_get "$config_file" "PANEL_USER")"
    panel_pass="$(monitor_config_get "$config_file" "PANEL_PASS")"
    panel_port="$(monitor_config_get "$config_file" "PANEL_PORT")"
    public_host="$(monitor_config_get "$config_file" "PANEL_PUBLIC_HOST")"
    public_scheme="$(monitor_config_get "$config_file" "PANEL_SCHEME")"

    echo
    echo "============================================================"
    echo "                    MONITOR DETAILS"
    echo "============================================================"
    echo "  Panel User  : ${panel_user:-admin}"
    echo "  Panel Pass  : ${panel_pass:-change-me}"
    echo "  Panel Link  : ${public_scheme:-http}://${public_host:-127.0.0.1}:${panel_port:-unknown}"
    echo "  Open Link   : copy/paste link above in browser"
    if run_with_sudo tmux has-session -t monitor-panel 2>/dev/null; then
        echo "  TMUX       : running (session: monitor-panel)"
    else
        echo "  TMUX       : stopped"
    fi
    echo "  Log File   : $monitor_home/monitor.log"
    echo "============================================================"
    echo
    monitor_show_runtime_commands
}

monitor_install() {
    local monitor_home="/home/monitor"
    local venv_dir="$monitor_home/venv"
    local monitor_script="$monitor_home/monitor_panel.py"
    local config_file="$monitor_home/config.env"
    local current_user=""
    local current_pass=""
    local current_bind=""
    local current_port=""
    local current_public_host=""
    local current_scheme=""
    local panel_user=""
    local panel_pass=""
    local panel_bind=""
    local panel_port=""
    local public_host=""
    local public_scheme=""
    local random_port=""

    show_monitor_banner
    monitor_show_action_ascii "install"
    info "Installing monitor requirements (python3, venv, tmux, iptables)..."
    info "Running: apt-get update -y"
    run_with_sudo apt-get update -y
    info "Running: apt-get install -y python3 python3-venv python3-pip tmux iptables curl"
    run_with_sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-pip tmux iptables curl

    info "Running: mkdir -p $monitor_home"
    run_with_sudo mkdir -p "$monitor_home"

    if [[ ! -d "$venv_dir" ]]; then
        info "Creating Python virtual environment..."
        info "Running: python3 -m venv $venv_dir"
        run_with_sudo python3 -m venv "$venv_dir"
    fi

    info "Installing Python dependencies in venv..."
    info "Running: $venv_dir/bin/pip install --upgrade pip"
    run_with_sudo "$venv_dir/bin/pip" install --upgrade pip >/dev/null
    info "Running: $venv_dir/bin/pip install flask"
    run_with_sudo "$venv_dir/bin/pip" install flask >/dev/null

    monitor_write_python_script "$monitor_script"

    if [[ -f "$config_file" ]]; then
        current_user="$(monitor_config_get "$config_file" "PANEL_USER")"
        current_pass="$(monitor_config_get "$config_file" "PANEL_PASS")"
        current_bind="$(monitor_config_get "$config_file" "PANEL_BIND")"
        current_port="$(monitor_config_get "$config_file" "PANEL_PORT")"
        current_public_host="$(monitor_config_get "$config_file" "PANEL_PUBLIC_HOST")"
        current_scheme="$(monitor_config_get "$config_file" "PANEL_SCHEME")"
    fi

    random_port="$(monitor_random_port)"
    panel_user="$(prompt_with_default "Monitor panel username" "${current_user:-admin}")"
    while [[ -z "$panel_user" ]]; do
        warn "Username cannot be empty."
        panel_user="$(prompt_with_default "Monitor panel username" "admin")"
    done

    read -r -p "$(printf '\033[1;36m%s\033[0m: ' "Monitor panel password (visible, Enter=keep current)")" panel_pass
    echo
    if [[ -z "$panel_pass" ]]; then
        panel_pass="${current_pass:-change-me}"
    fi

    panel_bind="$(prompt_with_default "Bind host" "${current_bind:-0.0.0.0}")"

    while true; do
        panel_port="$(prompt_with_default "Panel port (random default for safety)" "${current_port:-$random_port}")"
        if is_valid_port "$panel_port"; then
            break
        fi
        warn "Invalid port. Enter a number between 1 and 65535."
    done

    public_host="$(prompt_with_default "Public domain/IP for link" "${current_public_host:-$(monitor_detect_public_host)}")"
    while [[ -z "$public_host" ]]; do
        warn "Public domain/IP cannot be empty."
        public_host="$(prompt_with_default "Public domain/IP for link" "$(monitor_detect_public_host)")"
    done

    public_scheme="$(prompt_with_default "Public scheme (http or https)" "${current_scheme:-http}")"
    if [[ "$public_scheme" != "http" && "$public_scheme" != "https" ]]; then
        public_scheme="http"
    fi

    monitor_write_config_file "$config_file" "$panel_user" "$panel_pass" "$panel_bind" "$panel_port" "$public_host" "$public_scheme"
    monitor_start_tmux "$monitor_home"

    if command -v crontab &>/dev/null; then
        monitor_ensure_reboot_autostart "$monitor_home"
    else
        warn "crontab command not found. Auto-start on reboot was skipped."
    fi

    success "Monitor installed and running inside tmux session 'monitor-panel'."
    monitor_status
    if prompt_yes_no "Open live monitor logs now? (press q to quit)" "y"; then
        monitor_show_logs
    fi
}

monitor_edit() {
    local monitor_home="/home/monitor"
    local config_file="$monitor_home/config.env"
    local current_user=""
    local current_pass=""
    local current_bind=""
    local current_port=""
    local current_public_host=""
    local current_scheme=""
    local panel_user=""
    local panel_pass=""
    local panel_bind=""
    local panel_port=""
    local public_host=""
    local public_scheme=""
    local random_port=""

    if [[ ! -f "$config_file" ]]; then
        warn "Monitor config not found. Run: $0 monitor and choose option 1."
        return 1
    fi

    monitor_show_action_ascii "edit"
    current_user="$(monitor_config_get "$config_file" "PANEL_USER")"
    current_pass="$(monitor_config_get "$config_file" "PANEL_PASS")"
    current_bind="$(monitor_config_get "$config_file" "PANEL_BIND")"
    current_port="$(monitor_config_get "$config_file" "PANEL_PORT")"
    current_public_host="$(monitor_config_get "$config_file" "PANEL_PUBLIC_HOST")"
    current_scheme="$(monitor_config_get "$config_file" "PANEL_SCHEME")"
    random_port="$(monitor_random_port)"

    panel_user="$(prompt_with_default "Monitor panel username" "${current_user:-admin}")"
    while [[ -z "$panel_user" ]]; do
        warn "Username cannot be empty."
        panel_user="$(prompt_with_default "Monitor panel username" "admin")"
    done

    read -r -p "$(printf '\033[1;36m%s\033[0m: ' "Monitor panel password (visible, Enter=keep current)")" panel_pass
    echo
    if [[ -z "$panel_pass" ]]; then
        panel_pass="${current_pass:-change-me}"
    fi

    panel_bind="$(prompt_with_default "Bind host" "${current_bind:-0.0.0.0}")"

    while true; do
        panel_port="$(prompt_with_default "Panel port (random default for safety)" "${current_port:-$random_port}")"
        if is_valid_port "$panel_port"; then
            break
        fi
        warn "Invalid port. Enter a number between 1 and 65535."
    done

    public_host="$(prompt_with_default "Public domain/IP for link" "${current_public_host:-$(monitor_detect_public_host)}")"
    while [[ -z "$public_host" ]]; do
        warn "Public domain/IP cannot be empty."
        public_host="$(prompt_with_default "Public domain/IP for link" "$(monitor_detect_public_host)")"
    done

    public_scheme="$(prompt_with_default "Public scheme (http or https)" "${current_scheme:-http}")"
    if [[ "$public_scheme" != "http" && "$public_scheme" != "https" ]]; then
        public_scheme="http"
    fi

    monitor_write_config_file "$config_file" "$panel_user" "$panel_pass" "$panel_bind" "$panel_port" "$public_host" "$public_scheme"
    success "Monitor settings updated."
    monitor_restart
}

monitor_restart() {
    local monitor_home="/home/monitor"
    local monitor_script="$monitor_home/monitor_panel.py"
    local venv_python="$monitor_home/venv/bin/python3"

    if [[ ! -f "$monitor_script" || ! -x "$venv_python" ]]; then
        warn "Monitor is not fully installed. Run: $0 monitor and choose option 1."
        return 1
    fi

    monitor_show_action_ascii "restart"
    info "Restarting monitor panel..."
    monitor_start_tmux "$monitor_home"
    success "Monitor panel restarted in tmux session 'monitor-panel'."
    monitor_status
    if prompt_yes_no "Open live monitor logs now? (press q to quit)" "y"; then
        monitor_show_logs
    fi
}

monitor_show_logs() {
    local log_file="/home/monitor/monitor.log"
    local key=""
    local tail_pid=""

    monitor_show_action_ascii "logs"
    if [[ ! -f "$log_file" ]]; then
        warn "Log file not found yet: $log_file"
        return 1
    fi
    info "Live log view started. Press q to quit."
    run_with_sudo tail -n 80 -f "$log_file" &
    tail_pid=$!

    while true; do
        IFS= read -r -s -n1 key
        if [[ "$key" == "q" || "$key" == "Q" ]]; then
            break
        fi
    done

    run_with_sudo kill "$tail_pid" 2>/dev/null || kill "$tail_pid" 2>/dev/null || true
    wait "$tail_pid" 2>/dev/null || true
    echo
    info "Exited live log view."
    MONITOR_SKIP_PAUSE=1
}

monitor_menu() {
    local choice=""
    clear || true
    echo "  [1] Install or update monitoring system"
    echo "  [2] Edit panel username/password/settings"
    echo "  [3] Restart monitor panel"
    echo "  [4] Show panel details + direct link"
    echo "  [5] Live monitor logs (press q to quit)"
    echo "  [6] Show runtime commands"
    echo "  [7] Exit"
    read -r -p "$(printf '\033[1;36m%s\033[0m: ' "Select option [1-7]")" choice

    case "$choice" in
        1) monitor_install; return 1 ;;
        2) monitor_edit; return 1 ;;
        3) monitor_restart; return 1 ;;
        4) monitor_status; return 1 ;;
        5) monitor_show_logs; return 1 ;;
        6) monitor_show_runtime_commands; return 1 ;;
        7) return 0 ;;
        *) warn "Invalid option: $choice"; return 1 ;;
    esac
}

run_monitor() {
    MONITOR_SKIP_PAUSE=0
    while true; do
        if monitor_menu; then
            break
        fi
        if [[ "${MONITOR_SKIP_PAUSE:-0}" == "1" ]]; then
            MONITOR_SKIP_PAUSE=0
            continue
        fi
        echo
        read -r -p "$(printf '\033[1;36m%s\033[0m: ' "Press Enter to return to menu")" _
    done
}

# ------------------------------------------------------------
# STEP ALL: RUN EVERYTHING IN ORDER
# ------------------------------------------------------------
run_all() {
    show_core_action_ascii "all"
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
Usage: $0 {users|ssh|recaptcha|udgpw|bbr|sshtunnel|monitor|all} [port] [users_list]

  users      - Create users from list (comma-separated)
  ssh        - Change SSH port (default $SSH_PORT) and set ciphers
  recaptcha  - Run install_kernel.sh (reCAPTCHA step)
  udgpw      - Set UDPGW port to $UDPGW_PORT (silent, auto‑correct)
  bbr        - Enable BBR (install_kernel.sh second pass)
  sshtunnel  - Interactive SSH DNAT tunnel + optional reboot persistence
  monitor    - Interactive monitor menu (install/edit/restart/status/logs/commands)
  all        - Execute all steps in the correct order (requires users list)

Example:
  $0 users shayan,anothername
  $0 ssh 2233
  $0 sshtunnel
  $0 monitor
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
    monitor)    run_monitor ;;
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
