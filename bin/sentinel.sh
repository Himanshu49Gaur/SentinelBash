#!/usr/bin/env bash
# ==============================================================================
# SentinelBash - Master CLI Management & Daemon Orchestrator
# ==============================================================================
set -euo pipefail

CURRENT_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${CURRENT_SCRIPT_DIR}/common.sh"
load_config
init_sentinel_dirs

INGESTOR_PID_FILE="${SENTINEL_RUN_DIR}/ingestor.pid"
DETECTOR_PID_FILE="${SENTINEL_RUN_DIR}/detector.pid"

# Print tactical banner
print_banner() {
    echo -e "${CLR_CYAN}"
    cat <<'EOF'
  ___ ___ _  _ _____ ___ _  _ ___ _     ___    _   ___ _  _ 
 / __| __| \| |_   _|_ _| \| | __| |   | _ )  /_\ / __| || |
 \__ \ _|| .` | | |  | || .` | _|| |__ | _ \ / _ \\__ \ __ |
 |___/___|_|\_| |_| |___|_|\_|___|____|___/_/_/ \_\___/_||_|
EOF
    echo -e "   -- Mini-SOC Automation & Incident Response Engine v1.0.0 --${CLR_RESET}"
    echo ""
}

# Check if a daemon process is currently running
is_running() {
    local pid_file="$1"
    if [[ -f "$pid_file" ]]; then
        local pid
        pid="$(cat "$pid_file" 2>/dev/null || echo "")"
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

# Start all Sentinel daemons
start_daemons() {
    print_banner
    log_info "Initiating SentinelBash daemon cluster..."

    # 1. Start Ingestion Daemon
    if is_running "$INGESTOR_PID_FILE"; then
        log_warn "Ingestion daemon is already running [PID: $(cat "$INGESTOR_PID_FILE")]."
    else
        log_info "Launching Ingestion Daemon (ingestor.sh)..."
        nohup "${CURRENT_SCRIPT_DIR}/ingestor.sh" --daemon > "${SENTINEL_LOG_DIR}/ingestor.log" 2>&1 &
        local ing_pid=$!
        echo "$ing_pid" > "$INGESTOR_PID_FILE"
        sleep 0.5
        if kill -0 "$ing_pid" 2>/dev/null; then
            log_success "Ingestion Daemon started successfully [PID: ${ing_pid}]."
        else
            log_err "Failed to start Ingestion Daemon. Check ${SENTINEL_LOG_DIR}/ingestor.log."
        fi
    fi

    # 2. Start Detection Daemon
    if is_running "$DETECTOR_PID_FILE"; then
        log_warn "Detection daemon is already running [PID: $(cat "$DETECTOR_PID_FILE")]."
    else
        log_info "Launching Threat Detection Daemon (detector.sh)..."
        nohup "${CURRENT_SCRIPT_DIR}/detector.sh" --fifo > "${SENTINEL_LOG_DIR}/detector.log" 2>&1 &
        local det_pid=$!
        echo "$det_pid" > "$DETECTOR_PID_FILE"
        sleep 0.5
        if kill -0 "$det_pid" 2>/dev/null; then
            log_success "Detection Daemon started successfully [PID: ${det_pid}]."
        else
            log_err "Failed to start Detection Daemon. Check ${SENTINEL_LOG_DIR}/detector.log."
        fi
    fi

    echo ""
    log_success "SentinelBash core engine is OPERATIONAL."
}

# Stop all Sentinel daemons
stop_daemons() {
    log_info "Shutting down SentinelBash daemon cluster..."

    # Stop Detection Daemon
    if is_running "$DETECTOR_PID_FILE"; then
        local det_pid
        det_pid="$(cat "$DETECTOR_PID_FILE")"
        log_info "Sending SIGTERM to Detection Daemon [PID: ${det_pid}]..."
        kill "$det_pid" 2>/dev/null || true
        rm -f "$DETECTOR_PID_FILE"
        log_success "Detection Daemon stopped."
    else
        log_warn "Detection Daemon is not running."
        rm -f "$DETECTOR_PID_FILE"
    fi

    # Stop Ingestion Daemon
    if is_running "$INGESTOR_PID_FILE"; then
        local ing_pid
        ing_pid="$(cat "$INGESTOR_PID_FILE")"
        log_info "Sending SIGTERM to Ingestion Daemon [PID: ${ing_pid}]..."
        kill "$ing_pid" 2>/dev/null || true
        rm -f "$INGESTOR_PID_FILE"
        log_success "Ingestion Daemon stopped."
    else
        log_warn "Ingestion Daemon is not running."
        rm -f "$INGESTOR_PID_FILE"
    fi

    log_success "All SentinelBash daemons have been terminated."
}

# Restart daemons
restart_daemons() {
    stop_daemons
    sleep 1
    start_daemons
}

# Display system status
show_status() {
    print_banner
    echo -e "${CLR_WHITE}=== SYSTEM DAEMON STATUS ===${CLR_RESET}"
    
    if is_running "$INGESTOR_PID_FILE"; then
        echo -e "  Ingestion Engine: ${CLR_GREEN}ACTIVE${CLR_RESET} [PID: $(cat "$INGESTOR_PID_FILE")]"
    else
        echo -e "  Ingestion Engine: ${CLR_RED}STOPPED${CLR_RESET}"
    fi

    if is_running "$DETECTOR_PID_FILE"; then
        echo -e "  Detection Engine: ${CLR_GREEN}ACTIVE${CLR_RESET} [PID: $(cat "$DETECTOR_PID_FILE")]"
    else
        echo -e "  Detection Engine: ${CLR_RED}STOPPED${CLR_RESET}"
    fi

    local driver
    driver="$(detect_netfilter_driver)"
    echo -e "  Netfilter Driver: ${CLR_CYAN}${driver}${CLR_RESET}"
    echo -e "  Containment SOAR: ${CLR_GREEN}${CONTAINMENT_ENABLED}${CLR_RESET}"

    echo ""
    echo -e "${CLR_WHITE}=== SQLITE STATE ENGINE ===${CLR_RESET}"
    if [[ -f "${CURRENT_SCRIPT_DIR}/db.sh" && -f "${SENTINEL_ROOT_DIR}/data/sentinel.db" ]]; then
        "${CURRENT_SCRIPT_DIR}/db.sh" stats
    else
        echo "  Database not yet initialized. Run: python server/db/init_db.py"
    fi

    echo ""
    echo -e "${CLR_WHITE}=== ACTIVE CONTAINMENT RULES ===${CLR_RESET}"
    "${CURRENT_SCRIPT_DIR}/containment.sh" list

    echo ""
    echo -e "${CLR_WHITE}=== RECENT INCIDENTS GENERATED ===${CLR_RESET}"
    local inc_count=0
    if [[ -d "$SENTINEL_INCIDENT_DIR" ]]; then
        for inc_json in "${SENTINEL_INCIDENT_DIR}"/INC-*.json; do
            [[ ! -f "$inc_json" ]] && continue
            inc_count=$((inc_count + 1))
            local inc_id ip vec sev
            inc_id="$(grep -o '"incident_id": "[^"]*"' "$inc_json" | cut -d'"' -f4)"
            ip="$(grep -o '"attacker_ip": "[^"]*"' "$inc_json" | cut -d'"' -f4)"
            vec="$(grep -o '"attack_vector": "[^"]*"' "$inc_json" | cut -d'"' -f4)"
            sev="$(grep -o '"severity": "[^"]*"' "$inc_json" | cut -d'"' -f4)"
            printf "  %-20s | %-16s | %-18s | %s\n" "$inc_id" "$ip" "$vec" "$sev"
        done
    fi
    if (( inc_count == 0 )); then
        echo "  No recent incidents recorded in ${SENTINEL_INCIDENT_DIR}."
    fi
    echo ""
}

# Display configured detection rules
show_rules() {
    print_banner
    echo -e "${CLR_WHITE}=== CONFIGURATION & DETECTION RULES ===${CLR_RESET}"
    echo "  SSH Brute Force:      >= ${SSH_MAX_ATTEMPTS} failed attempts within ${SSH_WINDOW_SECONDS}s"
    echo "  Web Vulnerability:    >= ${WEB_PROBE_THRESHOLD} probes (traversal/.env/.git) within ${WEB_WINDOW_SECONDS}s"
    echo "  Privilege Escalation: >= ${SUDO_FAIL_THRESHOLD} sudo violations within ${SUDO_WINDOW_SECONDS}s"
    echo "  Ban Default Duration: ${DEFAULT_BAN_DURATION_SECONDS}s (1 hour)"
    echo "  Netfilter Driver:     $(detect_netfilter_driver) [Chain: ${IPTABLES_CHAIN}]"
    echo "  Log Path (Auth):      ${AUTH_LOG_PATH}"
    echo "  Log Path (Web):       ${WEB_LOG_PATH}"
    echo ""
}

# Display whitelist entries
show_whitelist() {
    print_banner
    echo -e "${CLR_WHITE}=== ACTIVE WHITELIST CONFIGURATION ===${CLR_RESET}"
    if [[ -f "$WHITELIST_FILE" ]]; then
        grep -v '^[[:space:]]*#' "$WHITELIST_FILE" | grep -v '^[[:space:]]*$' | while read -r entry; do
            echo "  [IMMUNE] $entry"
        done
    else
        echo "  Whitelist file not found at ${WHITELIST_FILE}."
    fi
    echo ""
}

# Print CLI usage guide
show_usage() {
    print_banner
    cat <<EOF
Usage: sentinel <command> [arguments]

Daemon Management:
  start              Start SentinelBash background daemons (ingestor & detector)
  stop               Gracefully stop all running SentinelBash daemons
  restart            Restart SentinelBash daemons
  status             Show health, daemon PIDs, active bans, and recent incidents

SOAR Containment:
  block <IP> [REASON] Immediately isolate an IP address via Netfilter
  unban <IP>          Remove containment rule for an IP address
  bans               List all currently quarantined attacker IPs
  flush              Flush all active containment rules applied by SentinelBash

Investigation & Observability:
  incidents          List all recorded forensic incident dossiers
  rules              Display current detection heuristics and thresholds
  whitelist          Display protected subnets and immunity addresses
  logs               Live tail the normalized security event stream

EOF
}

# Main Command Dispatcher
case "${1:-}" in
    start)
        start_daemons
        ;;
    stop)
        stop_daemons
        ;;
    restart)
        restart_daemons
        ;;
    status)
        show_status
        ;;
    block)
        shift
        "${CURRENT_SCRIPT_DIR}/containment.sh" block "$@"
        ;;
    unban)
        shift
        "${CURRENT_SCRIPT_DIR}/containment.sh" unban "$@"
        ;;
    bans)
        "${CURRENT_SCRIPT_DIR}/containment.sh" list
        ;;
    flush)
        "${CURRENT_SCRIPT_DIR}/containment.sh" flush
        ;;
    incidents)
        show_status
        ;;
    rules)
        show_rules
        ;;
    whitelist)
        show_whitelist
        ;;
    logs)
        log_info "Streaming normalized logs (Ctrl+C to exit)..."
        tail -n 30 -f "${SENTINEL_LOG_DIR}/normalized.log"
        ;;
    help|--help|-h|"")
        show_usage
        ;;
    *)
        log_err "Unknown command: '$1'"
        show_usage
        exit 1
        ;;
esac
