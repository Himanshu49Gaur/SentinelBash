#!/usr/bin/env bash
# ==============================================================================
# SentinelBash - Interactive Attack Simulator & SOC Defense Drill Lab
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck disable=SC1091
source "${PROJECT_ROOT}/bin/common.sh"
load_config
init_sentinel_dirs

print_banner() {
    echo -e "${CLR_PURPLE}"
    cat <<'EOF'
   ___ _____ _____ _   ___ _  __  ___ ___ __  __ _   _ _      _ _____ ___  ___ 
  /   \_   _   _/_\ / __| |/ / / __|_ _|  \/  | | | | |    /_\_   _/ _ \| _ \
  | - | | |   | |/ _ \ (__| ' <  \__ \| || |\/| | |_| | |__ / _ \| || (_) |   /
  |_|_| |_|   |_/_/ \_\___|_|\_\ |___/___|_|  |_|\___/|____/_/ \_\_| \___/|_|_\
EOF
    echo -e "      -- Synthetic Threat Injection & Latency Benchmark Lab --${CLR_RESET}"
    echo ""
}

# Scenario 1: SSH Brute Force
simulate_ssh_brute_force() {
    local target_ip="${1:-198.51.100.111}"
    local count="${2:-6}"
    log_security "Simulating Scenario A: SSH Brute Force Velocity (${count} attempts from ${target_ip})..."

    local start_time
    start_time="$(get_epoch)"

    # Stream failed auth attempts into auth log and feed as a batch
    local batch=""
    for i in $(seq 1 "$count"); do
        local line="Sep 25 00:00:0$i server sshd[$$]: Failed password for invalid user admin from ${target_ip} port $((30000 + i)) ssh2"
        echo "$line" >> "${AUTH_LOG_PATH}"
        batch="${batch}${line}"$'\n'
    done

    printf "%s" "$batch" | "${PROJECT_ROOT}/bin/ingestor.sh" --stdin auth | "${PROJECT_ROOT}/bin/detector.sh" --stdin >/dev/null

    local end_time
    end_time="$(get_epoch)"
    local latency=$(( end_time - start_time ))

    if "${PROJECT_ROOT}/bin/containment.sh" check "$target_ip" >/dev/null 2>&1; then
        log_success "SSH Attack successfully detected and quarantined in ${latency}s!"
        return 0
    else
        log_warn "Target IP was not quarantined in state."
        return 1
    fi
}

# Scenario 2: Web Exploit Scan
simulate_web_probes() {
    local target_ip="${1:-203.0.113.222}"
    log_security "Simulating Scenario B: Web Application Probes (Path traversal & sensitive file scans from ${target_ip})..."

    local payloads=(
        "GET /../../../../etc/passwd HTTP/1.1\" 404 162 \"-\" \"curl/8.0"
        "GET /.env HTTP/1.1\" 404 162 \"-\" \"gobuster/3.1"
        "GET /.git/config HTTP/1.1\" 404 162 \"-\" \"sqlmap/1.5"
        "GET /phpmyadmin/index.php HTTP/1.1\" 404 162 \"-\" \"nikto/2.1"
    )

    local start_time
    start_time="$(get_epoch)"

    local batch=""
    for payload in "${payloads[@]}"; do
        local line="${target_ip} - - [25/Sep/2026:00:00:05 +0000] \"${payload}\""
        echo "$line" >> "${WEB_LOG_PATH}"
        batch="${batch}${line}"$'\n'
    done

    printf "%s" "$batch" | "${PROJECT_ROOT}/bin/ingestor.sh" --stdin web | "${PROJECT_ROOT}/bin/detector.sh" --stdin >/dev/null

    local end_time
    end_time="$(get_epoch)"
    local latency=$(( end_time - start_time ))

    if "${PROJECT_ROOT}/bin/containment.sh" check "$target_ip" >/dev/null 2>&1; then
        log_success "Web Exploit Probe successfully detected and quarantined in ${latency}s!"
        return 0
    else
        log_warn "Target IP was not quarantined in state."
        return 1
    fi
}

# Scenario 3: Privilege Escalation Sudo Abuse
simulate_sudo_abuse() {
    log_security "Simulating Scenario C: Privilege Escalation (Sudo violations)..."

    local start_time
    start_time="$(get_epoch)"

    local batch=""
    for i in {1..4}; do
        local line="Sep 25 00:00:10 server sudo: suspicious_user : 3 incorrect password attempts ; TTY=pts/0 ; USER=root ; COMMAND=/bin/bash"
        echo "$line" >> "${SYS_LOG_PATH}"
        batch="${batch}${line}"$'\n'
    done

    printf "%s" "$batch" | "${PROJECT_ROOT}/bin/ingestor.sh" --stdin auth | "${PROJECT_ROOT}/bin/detector.sh" --stdin >/dev/null

    local end_time
    end_time="$(get_epoch)"
    local latency=$(( end_time - start_time ))
    log_success "Sudo Violation scenario executed in ${latency}s!"
    return 0
}

# Scenario 4: Whitelist Immunity Verification
simulate_whitelist_test() {
    local immune_ip="127.0.0.1"
    log_security "Simulating Scenario D: Whitelist Immunity Bypass Protection (${immune_ip})..."

    # Feed repeated failures from localhost
    for i in {1..6}; do
        local line="Sep 25 00:00:20 server sshd[$$]: Failed password for invalid user root from ${immune_ip} port 44444 ssh2"
        printf "%s\n" "$line" | "${PROJECT_ROOT}/bin/ingestor.sh" --stdin auth | "${PROJECT_ROOT}/bin/detector.sh" --stdin >/dev/null
    done

    if ! "${PROJECT_ROOT}/bin/containment.sh" check "$immune_ip" >/dev/null 2>&1; then
        log_success "DEFENSIVE RESILIENCE VERIFIED: Whitelisted IP ${immune_ip} was NOT blocked!"
    else
        log_err "CRITICAL FAILURE: Whitelisted IP was blocked!"
    fi
}

# Scenario 5: Run Full Defense Drill
run_all_scenarios() {
    print_banner
    log_info "Initiating Full SOC Automation Tactical Defense Drill..."
    echo ""

    simulate_ssh_brute_force "198.51.100.150" 6
    echo ""
    simulate_web_probes "203.0.113.160"
    echo ""
    simulate_sudo_abuse
    echo ""
    simulate_whitelist_test
    echo ""

    log_success "Full Tactical Defense Drill COMPLETED."
    echo ""
    "${PROJECT_ROOT}/bin/sentinel.sh" status
}

# Interactive Menu or Command Flags
case "${1:-}" in
    --ssh)
        print_banner
        simulate_ssh_brute_force "${2:-198.51.100.111}"
        ;;
    --web)
        print_banner
        simulate_web_probes "${2:-203.0.113.222}"
        ;;
    --sudo)
        print_banner
        simulate_sudo_abuse
        ;;
    --whitelist)
        print_banner
        simulate_whitelist_test
        ;;
    --all|"")
        run_all_scenarios
        ;;
    *)
        echo "Usage: $0 [--all | --ssh [ip] | --web [ip] | --sudo | --whitelist]"
        exit 1
        ;;
esac
