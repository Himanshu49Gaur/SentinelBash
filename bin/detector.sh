#!/usr/bin/env bash
# ==============================================================================
# SentinelBash - Sliding-Window Threat Detection Engine
# ==============================================================================
set -euo pipefail

CURRENT_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${CURRENT_SCRIPT_DIR}/common.sh"
load_config
init_sentinel_dirs

DETECTOR_PID_FILE="${SENTINEL_RUN_DIR}/detector.pid"

# Sliding window associative array: key = "${ip}_${vector}", value = "ts1 ts2 ts3..."
declare -A EVENT_WINDOWS
EVAL_COUNT=0

cleanup() {
    log_info "Stopping threat detector daemon..."
    rm -f "${DETECTOR_PID_FILE}"
    exit 0
}

trap cleanup SIGTERM SIGINT SIGHUP

# Generate a cryptographically distinct incident ID
generate_incident_id() {
    local date_part
    date_part="$(date +%Y%m%d)"
    local rand_part
    rand_part="$(head -c 4 /dev/urandom 2>/dev/null | xxd -p 2>/dev/null || date +%s%N | tail -c 6)"
    echo "INC-${date_part}-${rand_part}"
}

# Evaluate sliding window for a given IP, vector, threshold, and window size
# Returns 0 if threshold is breached, 1 otherwise (runs in current shell, NO subshell)
evaluate_window() {
    local ip="$1"
    local vector="$2"
    local epoch="$3"
    local threshold="$4"
    local window_size="$5"

    local key="${ip}_${vector}"
    local existing_timestamps="${EVENT_WINDOWS[$key]:-}"
    local valid_timestamps=()

    # Filter out expired timestamps outside the sliding window
    for ts in $existing_timestamps; do
        if (( (epoch - ts) <= window_size )); then
            valid_timestamps+=("$ts")
        fi
    done

    # Append current event epoch
    valid_timestamps+=("$epoch")
    EVENT_WINDOWS["$key"]="${valid_timestamps[*]}"

    local current_count="${#valid_timestamps[@]}"
    EVAL_COUNT="$current_count"

    if (( current_count >= threshold )); then
        # Threshold breached! Reset the window to avoid duplicate triggers
        EVENT_WINDOWS["$key"]=""
        return 0
    fi

    return 1
}

# Handle a confirmed threat trigger
handle_threat_trigger() {
    local ip="$1"
    local vector="$2"
    local severity="$3"
    local count="$4"
    local reason="$5"

    local inc_id
    inc_id="$(generate_incident_id)"

    log_security "THREAT THRESHOLD BREACHED: ${vector} from ${ip} (${count} attempts in window). Triggering containment..."

    # 1. Execute automated SOAR containment
    if [[ "${CONTAINMENT_ENABLED}" == "true" ]]; then
        "${CURRENT_SCRIPT_DIR}/containment.sh" block "$ip" "$inc_id" "$vector" "$reason" || true
    else
        log_warn "Containment is disabled in sentinel.conf (CONTAINMENT_ENABLED=false). Skipping firewall block."
    fi

    # 2. Compile forensic incident dossier
    local report_file=""
    report_file="$("${CURRENT_SCRIPT_DIR}/timeline.sh" compile "$inc_id" "$ip" "$vector" "$severity" "$count" "$reason" 2>/dev/null | tail -n 1 || echo "${SENTINEL_INCIDENT_DIR}/${inc_id}.md")"

    # 3. Synchronize with SQLite Database
    if [[ -f "${CURRENT_SCRIPT_DIR}/db.sh" ]]; then
        "${CURRENT_SCRIPT_DIR}/db.sh" insert-incident "$inc_id" "$ip" "$vector" "$severity" "$count" "CONTAINED" "$report_file" >/dev/null 2>&1 || true
    fi

    # 4. Dispatch Multi-Channel Notifications (Slack Block Kit / Webhooks)
    if [[ -f "${CURRENT_SCRIPT_DIR}/notifier.sh" ]]; then
        "${CURRENT_SCRIPT_DIR}/notifier.sh" dispatch "$inc_id" "$ip" "$vector" "$severity" "$reason" "$count" >/dev/null 2>&1 || true
    fi

    # 5. Log alert summary to alerts log
    local alert_log="${SENTINEL_LOG_DIR}/alerts.log"
    echo "$(get_timestamp)|${inc_id}|${severity}|${vector}|${ip}|${count}|${reason}" >> "$alert_log"
}

# Process an individual normalized record:
# Format: [EPOCH]|[SERVICE]|[IP]|[EVENT_TYPE]|[PAYLOAD]
process_event() {
    local record="$1"
    [[ -z "$record" ]] && return 0

    IFS='|' read -r epoch service ip event_type details <<< "$record"
    [[ -z "$ip" || -z "$event_type" ]] && return 0

    # Ensure IP is valid IPv4
    if ! is_valid_ipv4 "$ip"; then
        return 0
    fi

    # Heuristic Rule 1: SSH Brute Force
    if [[ "$service" == "sshd" && "$event_type" == "AUTH_FAILURE" ]]; then
        if evaluate_window "$ip" "SSH_BRUTE_FORCE" "$epoch" "$SSH_MAX_ATTEMPTS" "$SSH_WINDOW_SECONDS"; then
            handle_threat_trigger "$ip" "SSH_BRUTE_FORCE" "CRITICAL" "$EVAL_COUNT" "SSH brute force authentication threshold exceeded"
        fi
        return 0
    fi

    # Heuristic Rule 2: Web Reconnaissance & Exploit Scanning
    if [[ "$service" == "web" && ( "$event_type" == "WEB_PROBE" || "$event_type" == "WEB_ERROR" ) ]]; then
        if evaluate_window "$ip" "WEB_EXPLOIT_SCAN" "$epoch" "$WEB_PROBE_THRESHOLD" "$WEB_WINDOW_SECONDS"; then
            handle_threat_trigger "$ip" "WEB_EXPLOIT_SCAN" "HIGH" "$EVAL_COUNT" "Web application vulnerability scanning or probe attempts exceeded"
        fi
        return 0
    fi

    # Heuristic Rule 3: Privilege Escalation / Sudo Violation
    if [[ "$service" == "sudo" && "$event_type" == "SUDO_FAILURE" ]]; then
        if evaluate_window "$ip" "PRIV_ESC_ANOMALY" "$epoch" "$SUDO_FAIL_THRESHOLD" "$SUDO_WINDOW_SECONDS"; then
            handle_threat_trigger "$ip" "PRIV_ESC_ANOMALY" "CRITICAL" "$EVAL_COUNT" "Repeated sudo authentication failures or unauthorized privilege escalation"
        fi
        return 0
    fi
}

main() {
    local source_mode="fifo"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --stdin)
                source_mode="stdin"
                shift
                ;;
            --file)
                source_mode="file"
                local input_file="$2"
                shift 2
                ;;
            --fifo)
                source_mode="fifo"
                shift
                ;;
            *)
                echo "Usage: $0 [--fifo | --stdin | --file <normalized_log>]"
                exit 1
                ;;
        esac
    done

    echo $$ > "${DETECTOR_PID_FILE}"
    log_success "SentinelBash Threat Detection Engine active [PID: $$]"
    log_info "Configured Thresholds:"
    log_info "  - SSH Brute Force: >= ${SSH_MAX_ATTEMPTS} attempts in ${SSH_WINDOW_SECONDS}s"
    log_info "  - Web Exploit Probes: >= ${WEB_PROBE_THRESHOLD} probes in ${WEB_WINDOW_SECONDS}s"
    log_info "  - Sudo Abuse: >= ${SUDO_FAIL_THRESHOLD} violations in ${SUDO_WINDOW_SECONDS}s"

    case "$source_mode" in
        stdin)
            while IFS= read -r line || [[ -n "$line" ]]; do
                process_event "$line"
            done
            ;;
        file)
            if [[ ! -f "$input_file" ]]; then
                log_err "Input file ${input_file} not found."
                exit 1
            fi
            while IFS= read -r line || [[ -n "$line" ]]; do
                process_event "$line"
            done < "$input_file"
            ;;
        fifo)
            # Ensure FIFO exists
            if [[ ! -p "${SENTINEL_FIFO}" ]]; then
                rm -f "${SENTINEL_FIFO}"
                command -v mkfifo >/dev/null 2>&1 && mkfifo "${SENTINEL_FIFO}" || touch "${SENTINEL_FIFO}"
            fi

            log_info "Listening on FIFO stream: ${SENTINEL_FIFO}"
            # Open FIFO continuously in read loop
            while true; do
                if [[ -p "${SENTINEL_FIFO}" ]]; then
                    while IFS= read -r line; do
                        process_event "$line"
                    done < "${SENTINEL_FIFO}"
                else
                    # Fallback to tailing normalized.log if FIFO is not a pipe (e.g. non-POSIX filesystem)
                    local norm_log="${SENTINEL_LOG_DIR}/normalized.log"
                    [[ ! -f "$norm_log" ]] && touch "$norm_log"
                    tail -n 0 -F "$norm_log" 2>/dev/null | while IFS= read -r line; do
                        process_event "$line"
                    done
                fi
                sleep 0.5
            done
            ;;
    esac
}

main "$@"
