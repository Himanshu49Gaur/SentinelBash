#!/usr/bin/env bash
# ==============================================================================
# SentinelBash - Phase 4 Automated Test Suite
# Tests: Tactical SOC Web Console Assets, Attack Simulator & Deployment Configs
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck disable=SC1091
source "${PROJECT_ROOT}/bin/common.sh"
load_config
init_sentinel_dirs

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

assert_true() {
    local desc="$1"
    local cmd="$2"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if eval "$cmd" >/dev/null 2>&1; then
        echo -e "  ${CLR_GREEN}[PASS]${CLR_RESET} ${desc}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "  ${CLR_RED}[FAIL]${CLR_RESET} ${desc}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

assert_contains() {
    local desc="$1"
    local file="$2"
    local pattern="$3"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if grep -q -e "$pattern" "$file" 2>/dev/null; then
        echo -e "  ${CLR_GREEN}[PASS]${CLR_RESET} ${desc}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "  ${CLR_RED}[FAIL]${CLR_RESET} ${desc} (Pattern '${pattern}' not found in ${file})"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

echo ""
echo -e "${CLR_PURPLE}====================================================================${CLR_RESET}"
echo -e "${CLR_PURPLE}   SENTINELBASH PHASE 4 VERIFICATION SUITE                         ${CLR_RESET}"
echo -e "${CLR_PURPLE}   Scope: Web Assets, Deployment Units & Attack Simulation Lab      ${CLR_RESET}"
echo -e "${CLR_PURPLE}====================================================================${CLR_RESET}"
echo ""

# ------------------------------------------------------------------------------
# 1. Web Console Assets Integrity
# ------------------------------------------------------------------------------
echo -e "${CLR_CYAN}[1/3] Testing Web Console Assets & Design Implementation...${CLR_RESET}"

assert_true "index.html exists and is non-empty" "[[ -s '${PROJECT_ROOT}/static/index.html' ]]"
assert_true "style.css exists and is non-empty" "[[ -s '${PROJECT_ROOT}/static/css/style.css' ]]"
assert_true "app.js exists and is non-empty" "[[ -s '${PROJECT_ROOT}/static/js/app.js' ]]"

# Check critical DOM IDs in index.html
assert_contains "HTML contains live terminal container" "${PROJECT_ROOT}/static/index.html" "id=\"terminal-stream-container\""
assert_contains "HTML contains active bans KPI card" "${PROJECT_ROOT}/static/index.html" "id=\"kpi-active-bans\""
assert_contains "HTML contains active incidents KPI card" "${PROJECT_ROOT}/static/index.html" "id=\"kpi-total-incidents\""
assert_contains "HTML contains containment table body" "${PROJECT_ROOT}/static/index.html" "id=\"containment-table-body\""
assert_contains "HTML contains incident triage table body" "${PROJECT_ROOT}/static/index.html" "id=\"incidents-table-body\""
assert_contains "HTML contains forensic evidence drawer" "${PROJECT_ROOT}/static/index.html" "id=\"forensic-drawer\""
assert_contains "HTML contains manual quarantine modal" "${PROJECT_ROOT}/static/index.html" "id=\"quarantine-modal\""

# Check CSS Tokens in style.css
assert_contains "CSS implements Obsidian background variable" "${PROJECT_ROOT}/static/css/style.css" "--bg-canvas:"
assert_contains "CSS implements Cybernetic Accent color" "${PROJECT_ROOT}/static/css/style.css" "--accent-cyan:"
assert_contains "CSS implements Glassmorphism styling" "${PROJECT_ROOT}/static/css/style.css" "backdrop-filter"
assert_contains "CSS defines monospace terminal styling" "${PROJECT_ROOT}/static/css/style.css" "--font-mono"

# Check JS Controller logic in app.js
assert_contains "JS connects to SSE log stream" "${PROJECT_ROOT}/static/js/app.js" "/api/v1/stream/logs"
assert_contains "JS connects to SSE alerts stream" "${PROJECT_ROOT}/static/js/app.js" "/api/v1/stream/alerts"
assert_contains "JS implements manual quarantine routine" "${PROJECT_ROOT}/static/js/app.js" "/api/v1/containment/block"
assert_contains "JS implements emergency unban action" "${PROJECT_ROOT}/static/js/app.js" "handleUnbanIP"
assert_contains "JS implements drawer inspection" "${PROJECT_ROOT}/static/js/app.js" "openForensicDrawer"

# ------------------------------------------------------------------------------
# 2. Deployment Artifacts & Container Hardening
# ------------------------------------------------------------------------------
echo ""
echo -e "${CLR_CYAN}[2/3] Testing Deployment Units, Systemd & Containerization...${CLR_RESET}"

assert_true "sentinel-engine.service exists" "[[ -s '${PROJECT_ROOT}/deploy/sentinel-engine.service' ]]"
assert_contains "Engine service configures AmbientCapabilities CAP_NET_ADMIN" "${PROJECT_ROOT}/deploy/sentinel-engine.service" "CAP_NET_ADMIN"
assert_contains "Engine service executes sentinel.sh start" "${PROJECT_ROOT}/deploy/sentinel-engine.service" "sentinel.sh start"

assert_true "sentinel-api.service exists" "[[ -s '${PROJECT_ROOT}/deploy/sentinel-api.service' ]]"
assert_contains "API service executes uvicorn" "${PROJECT_ROOT}/deploy/sentinel-api.service" "uvicorn server.main:app"
assert_contains "API service runs as dedicated sentinel user" "${PROJECT_ROOT}/deploy/sentinel-api.service" "User=sentinel"

assert_true "deploy/install.sh exists and is executable" "[[ -x '${PROJECT_ROOT}/deploy/install.sh' ]]"
assert_contains "Installer sets up least-privilege sudoers" "${PROJECT_ROOT}/deploy/install.sh" "etc/sudoers.d/sentinelbash"

assert_true "Dockerfile exists" "[[ -s '${PROJECT_ROOT}/Dockerfile' ]]"
assert_contains "Dockerfile installs iptables" "${PROJECT_ROOT}/Dockerfile" "iptables"
assert_contains "Dockerfile exposes port 8000" "${PROJECT_ROOT}/Dockerfile" "EXPOSE 8000"

assert_true "docker-compose.yml exists" "[[ -s '${PROJECT_ROOT}/docker-compose.yml' ]]"
assert_contains "Compose grants NET_ADMIN capability" "${PROJECT_ROOT}/docker-compose.yml" "NET_ADMIN"

# ------------------------------------------------------------------------------
# 3. Attack Simulator & Threat Injection Verification
# ------------------------------------------------------------------------------
echo ""
echo -e "${CLR_CYAN}[3/3] Testing Attack Simulator Scenarios & Threat Response...${CLR_RESET}"

assert_true "simulate_attack.sh is executable" "[[ -x '${PROJECT_ROOT}/tests/simulate_attack.sh' ]]"

# Test A: Whitelist protection scenario
assert_true "Simulator Whitelist Immunity Drill executes successfully" \
    "bash '${PROJECT_ROOT}/tests/simulate_attack.sh' --whitelist"

# Flush previous test state
"${PROJECT_ROOT}/bin/containment.sh" flush >/dev/null 2>&1 || true

# Test B: SSH Brute Force Attack drill
assert_true "Simulator SSH Brute Force Drill triggers and isolates attacker" \
    "bash '${PROJECT_ROOT}/tests/simulate_attack.sh' --ssh 198.51.100.111 6"

# Verify that target IP is quarantined
assert_true "Target IP 198.51.100.111 is quarantined in state" \
    "'${PROJECT_ROOT}/bin/containment.sh' check 198.51.100.111"

# Verify manual unban
assert_true "Target IP 198.51.100.111 can be released via unban" \
    "'${PROJECT_ROOT}/bin/containment.sh' unban 198.51.100.111"

# Test C: Web Exploit Probe scenario
assert_true "Simulator Web Probe Drill triggers and isolates attacker" \
    "bash '${PROJECT_ROOT}/tests/simulate_attack.sh' --web 203.0.113.222"

# Verify target IP is quarantined
assert_true "Target IP 203.0.113.222 is quarantined in state" \
    "'${PROJECT_ROOT}/bin/containment.sh' check 203.0.113.222"

# Clean up
"${PROJECT_ROOT}/bin/containment.sh" flush >/dev/null 2>&1 || true

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
echo ""
echo -e "${CLR_PURPLE}====================================================================${CLR_RESET}"
echo -e "  PHASE 4 TEST SUMMARY: Passed: ${PASSED_TESTS}/${TOTAL_TESTS} | Failed: ${FAILED_TESTS}"
echo -e "${CLR_PURPLE}====================================================================${CLR_RESET}"

if [[ "$FAILED_TESTS" -eq 0 ]]; then
    echo -e "${CLR_GREEN}[SUCCESS] All Phase 4 specifications verified!${CLR_RESET}\n"
    exit 0
else
    echo -e "${CLR_RED}[FAILURE] Some specifications failed!${CLR_RESET}\n"
    exit 1
fi
