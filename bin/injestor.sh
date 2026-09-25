#!/usr/bin/env bash
# ==============================================================================
# SentinelBash - Real-Time Log Ingestion & Normalization Daemon
# ==============================================================================
set -euo pipefail

CURRENT_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${CURRENT_SCRIPT_DIR}/common.sh"
load_config
init_sentinel_dirs

# Ingestor PID file
INGESTOR_PID_FILE="${SENTINEL_RUN_DIR}/ingestor.pid"
NORMALIZED_LOG="${SENTINEL_LOG_DIR}/normalized.log"

# Clean up child processes on exit
cleanup() {
    log_info "Stopping log ingestion daemon and child subshells..."
    rm -f "${INGESTOR_PID_FILE}"
    # Kill any child processes in this process group
    trap - SIGTERM SIGINT SIGHUP EXIT
    kill -- -$$ 2>/dev/null || true
    exit 0
}

trap cleanup SIGTERM SIGINT SIGHUP

# Parse and normalize an SSH / Auth log line
parse_auth_line() {
    local line="$1"
    local epoch
    epoch="$(get_epoch)"

    # Look for Failed password or Invalid user
    if [[ "$line" =~ Failed[[:space:]]+password[[:space:]]+for[[:space:]]+(invalid[[:space:]]+user[[:space:]]+)?([^[:space:]]+)[[:space:]]+from[[:space:]]+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) ]]; then
        local user="${BASH_REMATCH[2]}"
        local ip="${BASH_REMATCH[3]}"
        echo "${epoch}|sshd|${ip}|AUTH_FAILURE|Failed password for user '${user}'"
        return 0
    fi

    # Look for Invalid user without explicit failed password keyword
    if [[ "$line" =~ Invalid[[:space:]]+user[[:space:]]+([^[:space:]]+)[[:space:]]+from[[:space:]]+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) ]]; then
        local user="${BASH_REMATCH[1]}"
        local ip="${BASH_REMATCH[2]}"
        echo "${epoch}|sshd|${ip}|AUTH_FAILURE|Invalid user attempt '${user}'"
        return 0
    fi

    # Look for Successful authentication
    if [[ "$line" =~ Accepted[[:space:]]+(password|publickey)[[:space:]]+for[[:space:]]+([^[:space:]]+)[[:space:]]+from[[:space:]]+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) ]]; then
        local method="${BASH_REMATCH[1]}"
        local user="${BASH_REMATCH[2]}"
        local ip="${BASH_REMATCH[3]}"
        echo "${epoch}|sshd|${ip}|AUTH_SUCCESS|Accepted ${method} for user '${user}'"
        return 0
    fi

    # Look for Sudo failure / privilege escalation attempt
    if [[ "$line" =~ sudo:.*(incorrect[[:space:]]+password|authentication[[:space:]]+failure|NOT[[:space:]]+in[[:space:]]+sudoers) ]]; then
        # Try to extract user
        local user="unknown"
        if [[ "$line" =~ sudo:[[:space:]]*([^[:space:]]+)[[:space:]]*: ]]; then
            user="${BASH_REMATCH[1]}"
        fi
        echo "${epoch}|sudo|127.0.0.1|SUDO_FAILURE|Sudo violation by '${user}': ${line}"
        return 0
    fi

    return 1
}

# Parse and normalize an Nginx / Apache web log line
parse_web_line() {
    local line="$1"
    local epoch
    epoch="$(get_epoch)"

    # Combined Log Format regex:
    # IP - - [date] "METHOD /path HTTP/1.1" status bytes "referer" "user_agent"
    local regex='^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+\[([^]]+)\][[:space:]]+"([A-Z]+)[[:space:]]+([^"[:space:]]+)[^"]*"[[:space:]]+([0-9]{3})[[:space:]]+[0-9-]+[[:space:]]+"([^"]*)"[[:space:]]+"([^"]*)"'

    if [[ "$line" =~ $regex ]]; then
        local ip="${BASH_REMATCH[1]}"
        local method="${BASH_REMATCH[3]}"
        local uri="${BASH_REMATCH[4]}"
        local status="${BASH_REMATCH[5]}"
        local user_agent="${BASH_REMATCH[7]}"

        # Check for attack signatures in URI
        local event_type="WEB_REQUEST"
        if [[ "$uri" =~ (\.\./|\.\.\\|/etc/passwd|\.env|\.git|phpmyadmin|wp-login|\.aws|shell\.php|cmd=) ]]; then
            event_type="WEB_PROBE"
        elif [[ "$status" =~ ^(401|403|404|500)$ ]]; then
            event_type="WEB_ERROR"
        fi

        echo "${epoch}|web|${ip}|${event_type}|${method} ${uri} [status:${status} agent:${user_agent}]"
        return 0
    fi

    return 1
}

# Process a single line from an identified service source
process_line() {
    local service="$1"
    local line="$2"
    local normalized=""

    case "$service" in
        auth|sshd)
            normalized="$(parse_auth_line "$line")" || true
            ;;
        web|nginx|apache)
            normalized="$(parse_web_line "$line")" || true
            ;;
        *)
            # Try auth first, then web
            normalized="$(parse_auth_line "$line" || parse_web_line "$line" || true)"
            ;;
    esac

    if [[ -n "$normalized" ]]; then
        # Append to persistent normalized log
        echo "$normalized" >> "${NORMALIZED_LOG}"

        # If FIFO exists and is a pipe, stream to FIFO without blocking
        if [[ -p "${SENTINEL_FIFO}" ]]; then
            echo "$normalized" > "${SENTINEL_FIFO}" 2>/dev/null || true
        fi

        # Output to stdout if running interactively
        if [[ "${EMIT_STDOUT:-false}" == "true" ]]; then
            echo "$normalized"
        fi
    fi
}

# Stream a log file using tail -F (survives log rotation)
stream_file() {
    local service="$1"
    local file_path="$2"

    if [[ ! -f "$file_path" ]]; then
        log_warn "Target log file ${file_path} does not exist. Creating empty file."
        touch "$file_path"
    fi

    log_info "Streaming ${service} logs from: ${file_path}"
    # Use tail -n 0 -F to follow appended lines and survive log rotation
    tail -n 0 -F "$file_path" 2>/dev/null | while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        process_line "$service" "$line"
    done
}

# Ensure FIFO is initialized
setup_fifo() {
    if [[ ! -p "${SENTINEL_FIFO}" ]]; then
        rm -f "${SENTINEL_FIFO}"
        if command -v mkfifo >/dev/null 2>&1; then
            mkfifo "${SENTINEL_FIFO}"
        else
            touch "${SENTINEL_FIFO}"
        fi
    fi
}

# Entrypoint
main() {
    local mode="daemon"
    export EMIT_STDOUT="false"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --stdout)
                export EMIT_STDOUT="true"
                shift
                ;;
            --file)
                local target_file="$2"
                local svc="${3:-auto}"
                shift 2
                [[ $# -gt 0 ]] && shift
                export EMIT_STDOUT="true"
                while IFS= read -r line || [[ -n "$line" ]]; do
                    [[ -z "$line" ]] && continue
                    process_line "$svc" "$line"
                done < "$target_file"
                exit 0
                ;;
            --stdin)
                local svc="${2:-auto}"
                shift
                [[ $# -gt 0 ]] && shift
                export EMIT_STDOUT="true"
                while IFS= read -r line || [[ -n "$line" ]]; do
                    [[ -z "$line" ]] && continue
                    process_line "$svc" "$line"
                done
                exit 0
                ;;
            --daemon)
                mode="daemon"
                shift
                ;;
            *)
                echo "Usage: $0 [--daemon | --stdout | --file <path> [service] | --stdin [service]]"
                exit 1
                ;;
        esac
    done

    echo $$ > "${INGESTOR_PID_FILE}"
    setup_fifo

    log_success "SentinelBash Ingestion Daemon active [PID: $$]"
    log_info "Monitoring Auth Log: ${AUTH_LOG_PATH}"
    log_info "Monitoring Web Log:  ${WEB_LOG_PATH}"
    log_info "Normalized Stream:   ${NORMALIZED_LOG}"
    log_info "Named Pipe (FIFO):   ${SENTINEL_FIFO}"

    # Stream auth log in background subshell
    stream_file "auth" "${AUTH_LOG_PATH}" &
    local auth_pid=$!

    # Stream web log in background subshell
    stream_file "web" "${WEB_LOG_PATH}" &
    local web_pid=$!

    # Wait for child processes
    wait "$auth_pid" "$web_pid"
}

main "$@"
