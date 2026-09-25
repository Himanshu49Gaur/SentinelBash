#!/usr/bin/env bash
# ==============================================================================
# SentinelBash - Netfilter Automated Containment (SOAR) Engine
# ==============================================================================
set -euo pipefail

CURRENT_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${CURRENT_SCRIPT_DIR}/common.sh"
load_config
init_sentinel_dirs

# Lock file to prevent concurrent containment race conditions
LOCK_FILE="${SENTINEL_RUN_DIR}/containment.lock"

acquire_lock() {
    local max_wait=5
    local waited=0
    while ! mkdir "${LOCK_FILE}" 2>/dev/null; do
        sleep 0.1
        waited=$((waited + 1))
        if (( waited > max_wait * 10 )); then
            log_warn "Containment lock acquisition timed out. Clearing stale lock."
            rm -rf "${LOCK_FILE}"
        fi
    done
}

release_lock() {
    rm -rf "${LOCK_FILE}" 2>/dev/null || true
}

# Check if an IP is currently banned in state file
is_ip_banned() {
    local ip="$1"
    if [[ ! -f "$BANS_STATE_FILE" ]]; then
        return 1
    fi
    grep -q "|${ip}|" "$BANS_STATE_FILE" 2>/dev/null
}

# Apply netfilter drop rule based on detected driver
apply_firewall_drop() {
    local ip="$1"
    local inc_id="$2"
    local driver="${3:-mock}"

    case "$driver" in
        iptables)
            log_info "Executing Netfilter DROP: iptables -I ${IPTABLES_CHAIN} -s ${ip} -j DROP -m comment --comment \"${IPTABLES_TAG_PREFIX}:${inc_id}\""
            # Check if duplicate rule already exists in iptables
            if ! iptables -C "${IPTABLES_CHAIN}" -s "${ip}" -j DROP -m comment --comment "${IPTABLES_TAG_PREFIX}:${inc_id}" 2>/dev/null; then
                iptables -I "${IPTABLES_CHAIN}" 1 -s "${ip}" -j DROP -m comment --comment "${IPTABLES_TAG_PREFIX}:${inc_id}"
            else
                log_warn "iptables rule for ${ip} already present in kernel chain."
            fi
            ;;
        ufw)
            log_info "Executing UFW Deny: ufw insert 1 deny from ${ip} to any comment \"${IPTABLES_TAG_PREFIX}:${inc_id}\""
            ufw insert 1 deny from "${ip}" to any comment "${IPTABLES_TAG_PREFIX}:${inc_id}" >/dev/null
            ;;
        mock|*)
            log_info "[MOCK DRIVER] Simulated Netfilter DROP rule applied for IP: ${ip} [Tag: ${IPTABLES_TAG_PREFIX}:${inc_id}]"
            ;;
    esac
}

# Revoke netfilter drop rule
remove_firewall_drop() {
    local ip="$1"
    local inc_id="${2:-}"
    local driver
    driver="$(detect_netfilter_driver)"

    case "$driver" in
        iptables)
            log_info "Revoking iptables rule for IP: ${ip}"
            # Delete any rule matching this IP with our comment tag or direct match
            while iptables -D "${IPTABLES_CHAIN}" -s "${ip}" -j DROP 2>/dev/null; do
                :
            done
            ;;
        ufw)
            log_info "Revoking UFW deny rule for IP: ${ip}"
            ufw delete deny from "${ip}" to any >/dev/null 2>&1 || true
            ;;
        mock|*)
            log_info "[MOCK DRIVER] Revoked Netfilter DROP rule for IP: ${ip}"
            ;;
    esac
}

# Block an IP
block_ip() {
    local ip="$1"
    local inc_id="${2:-INC-$(date +%s%N | cut -b1-12)}"
    local vector="${3:-MANUAL}"
    local reason="${4:-Operator or automated quarantine}"
    local duration="${5:-${DEFAULT_BAN_DURATION_SECONDS}}"

    # 1. Validate IP format
    if ! is_valid_ipv4 "$ip"; then
        log_err "Invalid IPv4 address format: '${ip}'. Containment aborted."
        return 1
    fi

    # 2. Whitelist Immunity Guard
    if is_whitelisted "$ip"; then
        log_warn "IMMUNITY GUARD: IP ${ip} is in whitelist! Containment explicitly bypassed."
        return 2
    fi

    acquire_lock
    trap release_lock EXIT

    # 3. Duplicate Suppression Guard
    if is_ip_banned "$ip"; then
        log_warn "DUPLICATE SUPPRESSION: IP ${ip} is already quarantined in active bans."
        release_lock
        return 0
    fi

    # 4. Enforce Netfilter Drop
    local driver
    driver="$(detect_netfilter_driver)"
    apply_firewall_drop "$ip" "$inc_id" "$driver"

    # 5. Record State
    local ban_epoch
    ban_epoch="$(get_epoch)"
    local expires_epoch=0
    if (( duration > 0 )); then
        expires_epoch=$(( ban_epoch + duration ))
    fi

    # Format: [BAN_EPOCH]|[IP]|[INCIDENT_ID]|[VECTOR]|[DURATION]|[EXPIRES_EPOCH]|[DRIVER]|[REASON]
    echo "${ban_epoch}|${ip}|${inc_id}|${vector}|${duration}|${expires_epoch}|${driver}|${reason}" >> "$BANS_STATE_FILE"

    # Sync to SQLite database
    if [[ -f "${CURRENT_SCRIPT_DIR}/db.sh" ]]; then
        "${CURRENT_SCRIPT_DIR}/db.sh" insert-firewall "FW-${inc_id}" "${inc_id}" "${ip}" "${IPTABLES_TAG_PREFIX}:${inc_id}" "DROP" >/dev/null 2>&1 || true
    fi

    log_security "CONTAINMENT ACTIVE: Attacker IP ${ip} isolated. Incident: ${inc_id}, Vector: ${vector}"
    release_lock
    return 0
}

# Unban an IP
unban_ip() {
    local ip="$1"

    if ! is_valid_ipv4 "$ip"; then
        log_err "Invalid IPv4 address: '${ip}'"
        return 1
    fi

    acquire_lock
    trap release_lock EXIT

    if ! is_ip_banned "$ip"; then
        log_warn "IP ${ip} was not found in active bans."
        # Still attempt firewall cleanup in case of orphaned rule
        remove_firewall_drop "$ip"
        if [[ -f "${CURRENT_SCRIPT_DIR}/db.sh" ]]; then
            "${CURRENT_SCRIPT_DIR}/db.sh" deactivate-firewall "${ip}" >/dev/null 2>&1 || true
        fi
        release_lock
        return 0
    fi

    remove_firewall_drop "$ip"

    # Sync to SQLite database
    if [[ -f "${CURRENT_SCRIPT_DIR}/db.sh" ]]; then
        "${CURRENT_SCRIPT_DIR}/db.sh" deactivate-firewall "${ip}" >/dev/null 2>&1 || true
    fi

    # Remove from state file
    local tmp_file="${SENTINEL_RUN_DIR}/bans_tmp.$$"
    grep -v "|${ip}|" "$BANS_STATE_FILE" > "$tmp_file" 2>/dev/null || true
    mv -f "$tmp_file" "$BANS_STATE_FILE"

    log_success "CONTAINMENT LIFTED: IP ${ip} has been restored."
    release_lock
    return 0
}

# List all active bans
list_bans() {
    if [[ ! -s "$BANS_STATE_FILE" ]]; then
        echo "No active IP containment rules currently enforced."
        return 0
    fi

    local has_entries=false
    while IFS='|' read -r epoch ip inc_id vector duration expires driver reason || [[ -n "$epoch" ]]; do
        [[ -z "$ip" ]] && continue
        if [[ "$has_entries" == "false" ]]; then
            echo -e "${CLR_CYAN}========================================================================================${CLR_RESET}"
            printf "%-20s %-16s %-16s %-18s %-8s %s\n" "QUARANTINE TIME" "IP ADDRESS" "INCIDENT ID" "ATTACK VECTOR" "DRIVER" "REASON"
            echo -e "${CLR_CYAN}----------------------------------------------------------------------------------------${CLR_RESET}"
            has_entries=true
        fi
        local formatted_time
        formatted_time="$(date -u -d "@${epoch}" +"%Y-%m-%d %H:%M:%S" 2>/dev/null || date -u -r "${epoch}" +"%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "$epoch")"
        printf "%-20s %-16s %-16s %-18s %-8s %s\n" "$formatted_time" "$ip" "$inc_id" "$vector" "$driver" "$reason"
    done < "$BANS_STATE_FILE"

    if [[ "$has_entries" == "true" ]]; then
        echo -e "${CLR_CYAN}========================================================================================${CLR_RESET}"
    else
        echo "No active IP containment rules currently enforced."
    fi
}

# Flush all Sentinel bans
flush_bans() {
    log_warn "Flushing all Sentinel containment rules..."
    acquire_lock
    trap release_lock EXIT

    if [[ -f "$BANS_STATE_FILE" ]]; then
        while IFS='|' read -r epoch ip inc_id vector duration expires driver reason || [[ -n "$epoch" ]]; do
            [[ -z "$ip" ]] && continue
            remove_firewall_drop "$ip" "$inc_id"
        done < "$BANS_STATE_FILE"
        > "$BANS_STATE_FILE"
    fi

    log_success "All Sentinel containment rules have been flushed."
    release_lock
}

# CLI Interface
case "${1:-}" in
    block)
        shift
        block_ip "$@"
        ;;
    unban)
        shift
        unban_ip "$@"
        ;;
    list|status)
        list_bans
        ;;
    check)
        shift
        if is_ip_banned "$1"; then
            echo "BANNED"
            exit 0
        else
            echo "CLEAN"
            exit 1
        fi
        ;;
    flush)
        flush_bans
        ;;
    *)
        echo "Usage: $0 {block <ip> [inc_id] [vector] [reason] [duration] | unban <ip> | list | check <ip> | flush}"
        exit 1
        ;;
esac

