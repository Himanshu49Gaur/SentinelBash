#!/usr/bin/env bash
# ==============================================================================
# SentinelBash - Common Library & System Utilities
# ==============================================================================
set -euo pipefail

# Determine script and project directory root
CURRENT_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SENTINEL_ROOT_DIR="$(cd "${CURRENT_SCRIPT_DIR}/.." && pwd)"

# ANSI Color Codes for tactical terminal styling
CLR_RESET="\033[0m"
CLR_RED="\033[1;31m"
CLR_GREEN="\033[1;32m"
CLR_YELLOW="\033[1;33m"
CLR_BLUE="\033[1;34m"
CLR_PURPLE="\033[1;35m"
CLR_CYAN="\033[1;36m"
CLR_WHITE="\033[1;37m"
CLR_GRAY="\033[0;90m"

# Logging Utilities
get_timestamp() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

get_epoch() {
    date +%s
}

log_info() {
    echo -e "${CLR_GRAY}[$(get_timestamp)]${CLR_RESET} ${CLR_CYAN}[INFO]${CLR_RESET} $*"
}

log_success() {
    echo -e "${CLR_GRAY}[$(get_timestamp)]${CLR_RESET} ${CLR_GREEN}[SUCCESS]${CLR_RESET} $*"
}

log_warn() {
    echo -e "${CLR_GRAY}[$(get_timestamp)]${CLR_RESET} ${CLR_YELLOW}[WARN]${CLR_RESET} $*" >&2
}

log_err() {
    echo -e "${CLR_GRAY}[$(get_timestamp)]${CLR_RESET} ${CLR_RED}[ERROR]${CLR_RESET} $*" >&2
}

log_security() {
    echo -e "${CLR_GRAY}[$(get_timestamp)]${CLR_RESET} ${CLR_PURPLE}[SECURITY]${CLR_RESET} $*"
}

# Resolve path relative to project root if not absolute
resolve_path() {
    local target_path="$1"
    if [[ "$target_path" = /* ]] || [[ "$target_path" =~ ^[a-zA-Z]:[/\\] ]]; then
        echo "$target_path"
    else
        echo "${SENTINEL_ROOT_DIR}/${target_path}"
    fi
}

# Load Configuration
load_config() {
    local config_file="${1:-${SENTINEL_ROOT_DIR}/config/sentinel.conf}"
    if [[ -f "$config_file" ]]; then
        # Source the configuration
        # shellcheck disable=SC1090
        source "$config_file"
    else
        log_warn "Configuration file not found at ${config_file}. Using defaults."
    fi

    # Resolve paths
    export SENTINEL_LOG_DIR="$(resolve_path "${SENTINEL_LOG_DIR:-data/logs}")"
    export SENTINEL_RUN_DIR="$(resolve_path "${SENTINEL_RUN_DIR:-data/run}")"
    export SENTINEL_INCIDENT_DIR="$(resolve_path "${SENTINEL_INCIDENT_DIR:-data/incidents}")"
    export SENTINEL_FIFO="$(resolve_path "${SENTINEL_FIFO:-data/run/sentinel.fifo}")"
    export WHITELIST_FILE="$(resolve_path "${WHITELIST_FILE:-config/whitelist.conf}")"
    export BANS_STATE_FILE="$(resolve_path "${BANS_STATE_FILE:-data/run/active_bans.state}")"
    export AUTH_LOG_PATH="$(resolve_path "${AUTH_LOG_PATH:-data/logs/auth.log}")"
    export WEB_LOG_PATH="$(resolve_path "${WEB_LOG_PATH:-data/logs/nginx_access.log}")"
    export SYS_LOG_PATH="$(resolve_path "${SYS_LOG_PATH:-data/logs/syslog}")"

    # Threshold defaults
    export SSH_MAX_ATTEMPTS="${SSH_MAX_ATTEMPTS:-5}"
    export SSH_WINDOW_SECONDS="${SSH_WINDOW_SECONDS:-60}"
    export WEB_PROBE_THRESHOLD="${WEB_PROBE_THRESHOLD:-3}"
    export WEB_WINDOW_SECONDS="${WEB_WINDOW_SECONDS:-45}"
    export SUDO_FAIL_THRESHOLD="${SUDO_FAIL_THRESHOLD:-3}"
    export SUDO_WINDOW_SECONDS="${SUDO_WINDOW_SECONDS:-60}"
    export CONTAINMENT_ENABLED="${CONTAINMENT_ENABLED:-true}"
    export NETFILTER_DRIVER="${NETFILTER_DRIVER:-auto}"
    export IPTABLES_CHAIN="${IPTABLES_CHAIN:-INPUT}"
    export IPTABLES_TAG_PREFIX="${IPTABLES_TAG_PREFIX:-SENTINEL}"
    export DEFAULT_BAN_DURATION_SECONDS="${DEFAULT_BAN_DURATION_SECONDS:-3600}"
}

# Ensure Runtime Directories Exist
init_sentinel_dirs() {
    mkdir -p "${SENTINEL_LOG_DIR}"
    mkdir -p "${SENTINEL_RUN_DIR}"
    mkdir -p "${SENTINEL_INCIDENT_DIR}"

    if [[ ! -f "${BANS_STATE_FILE}" ]]; then
        touch "${BANS_STATE_FILE}"
    fi

    # Ensure log targets exist as files so tail won't fail
    if [[ ! -f "${AUTH_LOG_PATH}" ]]; then
        touch "${AUTH_LOG_PATH}"
    fi
    if [[ ! -f "${WEB_LOG_PATH}" ]]; then
        touch "${WEB_LOG_PATH}"
    fi
    if [[ ! -f "${SYS_LOG_PATH}" ]]; then
        touch "${SYS_LOG_PATH}"
    fi
}

# IPv4 Validator
is_valid_ipv4() {
    local ip="$1"
    local rx='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    if [[ ! "$ip" =~ $rx ]]; then
        return 1
    fi

    local IFS='.'
    read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if (( octet < 0 || octet > 255 )); then
            return 1
        fi
    done
    return 0
}

# Convert IPv4 to 32-bit unsigned integer
ipv4_to_int() {
    local ip="$1"
    local IFS='.'
    read -r o1 o2 o3 o4 <<< "$ip"
    echo "$(( (o1 << 24) + (o2 << 16) + (o3 << 8) + o4 ))"
}

# Check if an IPv4 address is inside a CIDR block (e.g. 192.168.1.50 in 192.168.0.0/16)
ip_in_cidr() {
    local ip="$1"
    local cidr="$2"

    if [[ "$cidr" != *"/"* ]]; then
        # Exact match
        [[ "$ip" == "$cidr" ]]
        return $?
    fi

    local network="${cidr%/*}"
    local prefix="${cidr#*/}"

    if ! is_valid_ipv4 "$ip" || ! is_valid_ipv4 "$network"; then
        return 1
    fi

    if (( prefix < 0 || prefix > 32 )); then
        return 1
    fi

    if (( prefix == 0 )); then
        return 0
    fi

    local ip_int
    local net_int
    ip_int="$(ipv4_to_int "$ip")"
    net_int="$(ipv4_to_int "$network")"

    # Calculate mask in 32-bit arithmetic
    local mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
    
    local ip_masked=$(( ip_int & mask ))
    local net_masked=$(( net_int & mask ))

    (( ip_masked == net_masked ))
}

# Whitelist Verification Function
is_whitelisted() {
    local ip="$1"

    # Fast check: localhost and loopback
    if [[ "$ip" == "127.0.0.1" || "$ip" == "::1" || "$ip" == "localhost" ]]; then
        return 0
    fi

    if [[ ! -f "$WHITELIST_FILE" ]]; then
        log_warn "Whitelist file not found at ${WHITELIST_FILE}. Permitting containment."
        return 1
    fi

    # Read whitelist entries (ignoring comments and empty lines)
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Strip trailing carriage returns and whitespace
        line="$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/\r$//')"
        # Skip empty lines and comments
        [[ -z "$line" || "$line" =~ ^# ]] && continue

        # Extract entry before any inline comment
        local entry
        entry="$(echo "$line" | awk '{print $1}')"

        if [[ "$entry" == "$ip" ]]; then
            return 0
        fi

        # If entry is a CIDR and candidate is valid IPv4
        if [[ "$entry" == *"/"* ]] && is_valid_ipv4 "$ip"; then
            if ip_in_cidr "$ip" "$entry"; then
                return 0
            fi
        fi
    done < "$WHITELIST_FILE"

    return 1
}

# Netfilter Driver Detection
detect_netfilter_driver() {
    if [[ "${NETFILTER_DRIVER}" != "auto" ]]; then
        echo "${NETFILTER_DRIVER}"
        return 0
    fi

    # Check for Linux root or sudo capabilities with iptables
    if command -v iptables >/dev/null 2>&1; then
        # Test if we can query iptables
        if iptables -L -n >/dev/null 2>&1; then
            echo "iptables"
            return 0
        fi
    fi

    if command -v ufw >/dev/null 2>&1; then
        if ufw status >/dev/null 2>&1; then
            echo "ufw"
            return 0
        fi
    fi

    # Fall back to mock driver for development / non-root / Windows / Darwin
    echo "mock"
}

