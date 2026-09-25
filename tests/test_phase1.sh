#!/usr/bin/env bash
# ==============================================================================
# SentinelBash - Phase 1 Automated Verification & Test Suite
# ==============================================================================
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${TEST_DIR}/.." && pwd)"

# shellcheck disable=SC1091
source "${PROJECT_ROOT}/bin/common.sh"
load_config
init_sentinel_dirs

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

assert_eq() {
    local test_name="$1"
    local expected="$2"
    local actual="$3"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if [[ "$expected" == "$actual" ]]; then
        echo -e "  [PASS] ${test_name}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "  [FAIL] ${test_name} (Expected: '${expected}', Got: '${actual}')" >&2
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

assert_true() {
    local test_name="$1"
    local command="$2"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if eval "$command"; then
        echo -e "  [PASS] ${test_name}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "  [FAIL] ${test_name} (Command failed: ${command})" >&2
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

assert_false() {
    local test_name="$1"
    local command="$2"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if ! eval "$command"; then
        echo -e "  [PASS] ${test_name}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "  [FAIL] ${test_name} (Expected command to fail: ${command})" >&2
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

echo -e "${CLR_CYAN}======================================================================${CLR_RESET}"
echo -e "${CLR_WHITE}   SentinelBash Phase 1: Core Engine Test Suite   ${CLR_RESET}"
echo -e "${CLR_CYAN}======================================================================${CLR_RESET}"
echo ""

# ------------------------------------------------------------------------------
# Test Suite 1: IP Validation & Whitelist Logic
# ------------------------------------------------------------------------------
echo -e "${CLR_YELLOW}[Test Group 1: IP Validation & Whitelist Rules]${CLR_RESET}"

assert_true "Valid IPv4 loopback" "is_valid_ipv4 '127.0.0.1'"
assert_true "Valid IPv4 public" "is_valid_ipv4 '198.51.100.25'"
assert_false "Invalid IPv4 octet > 255" "is_valid_ipv4 '192.168.1.300'"
assert_false "Invalid IPv4 characters" "is_valid_ipv4 'invalid.ip.string'"
assert_false "Invalid IPv4 too many octets" "is_valid_ipv4 '1.2.3.4.5'"

assert_true "CIDR match 10.0.0.0/8" "ip_in_cidr '10.25.1.99' '10.0.0.0/8'"
assert_false "CIDR no match 10.0.0.0/8" "ip_in_cidr '11.0.0.1' '10.0.0.0/8'"
assert_true "CIDR match 192.168.0.0/16" "ip_in_cidr '192.168.10.50' '192.168.0.0/16'"

assert_true "Whitelist matches 127.0.0.1" "is_whitelisted '127.0.0.1'"
assert_true "Whitelist matches 10.1.2.3" "is_whitelisted '10.1.2.3'"
assert_false "Attacker 203.0.113.100 not whitelisted" "is_whitelisted '203.0.113.100'"
echo ""

# ------------------------------------------------------------------------------
# Test Suite 2: Ingestion & Normalization
# ------------------------------------------------------------------------------
echo -e "${CLR_YELLOW}[Test Group 2: Log Normalization Engine]${CLR_RESET}"

# Test SSH failure log line
ssh_sample="Sep 24 04:00:01 server sshd[1234]: Failed password for invalid user admin from 198.51.100.66 port 38290 ssh2"
parsed_ssh="$(printf "%s\n" "$ssh_sample" | "${PROJECT_ROOT}/bin/ingestor.sh" --stdin auth)"
assert_true "SSH failure record normalized" "[[ '$parsed_ssh' =~ \|sshd\|198\.51\.100\.66\|AUTH_FAILURE\|Failed\ password ]]"

# Test Web exploit probe line
web_sample='198.51.100.66 - - [24/Sep/2026:04:00:02 +0000] "GET /etc/passwd HTTP/1.1" 404 153 "-" "curl/8.0"'
parsed_web="$(printf "%s\n" "$web_sample" | "${PROJECT_ROOT}/bin/ingestor.sh" --stdin web)"
assert_true "Web probe record normalized" "[[ '$parsed_web' =~ \|web\|198\.51\.100\.66\|WEB_PROBE\|GET\ /etc/passwd ]]"

# Test Sudo failure line
sudo_sample="Sep 24 04:00:05 server sudo: testuser : 3 incorrect password attempts ; TTY=pts/0 ; USER=root ; COMMAND=/bin/bash"
parsed_sudo="$(printf "%s\n" "$sudo_sample" | "${PROJECT_ROOT}/bin/ingestor.sh" --stdin auth)"
assert_true "Sudo violation normalized" "[[ '$parsed_sudo' =~ \|sudo\|127\.0\.0\.1\|SUDO_FAILURE\| ]]"
echo ""

# ------------------------------------------------------------------------------
# Test Suite 3: Netfilter Automated Containment
# ------------------------------------------------------------------------------
echo -e "${CLR_YELLOW}[Test Group 3: Netfilter Containment & Whitelist Immunity]${CLR_RESET}"

# Clean existing state
"${PROJECT_ROOT}/bin/containment.sh" flush >/dev/null

target_test_ip="203.0.113.88"

# 1. Block attacker
"${PROJECT_ROOT}/bin/containment.sh" block "$target_test_ip" "INC-P1-001" "SSH_BRUTE_FORCE" "Unit test containment" >/dev/null
assert_true "Attacker IP quarantined in state" "'${PROJECT_ROOT}/bin/containment.sh' check '$target_test_ip'"

# 2. Duplicate suppression
output_dup="$("${PROJECT_ROOT}/bin/containment.sh" block "$target_test_ip" "INC-P1-002" "SSH_BRUTE_FORCE" 2>&1 || true)"
assert_true "Duplicate suppression logged" "[[ '$output_dup' =~ DUPLICATE\ SUPPRESSION ]]"

# 3. Whitelist immunity
output_wl="$("${PROJECT_ROOT}/bin/containment.sh" block "127.0.0.1" "INC-P1-003" "MANUAL" 2>&1 || true)"
assert_true "Whitelist immunity enforced" "[[ '$output_wl' =~ IMMUNITY\ GUARD ]]"

# 4. Unban attacker
"${PROJECT_ROOT}/bin/containment.sh" unban "$target_test_ip" >/dev/null
assert_false "Quarantine lifted from state" "'${PROJECT_ROOT}/bin/containment.sh' check '$target_test_ip'"
echo ""

# ------------------------------------------------------------------------------
# Test Suite 4: Threat Detection (Sliding Window Algorithm)
# ------------------------------------------------------------------------------
echo -e "${CLR_YELLOW}[Test Group 4: Sliding-Window Threat Detection]${CLR_RESET}"

attacker_sim_ip="198.51.100.95"
now_ts="$(get_epoch)"

# Clean any residual bans
"${PROJECT_ROOT}/bin/containment.sh" unban "$attacker_sim_ip" >/dev/null 2>&1 || true

# Feed 4 events (below threshold of 5)
input_stream_4=""
for i in {1..4}; do
    input_stream_4="${input_stream_4}${now_ts}|sshd|${attacker_sim_ip}|AUTH_FAILURE|Failed password attempt ${i}"$'\n'
done

printf "%s" "$input_stream_4" | "${PROJECT_ROOT}/bin/detector.sh" --stdin >/dev/null
assert_false "Threshold not breached at 4 attempts" "'${PROJECT_ROOT}/bin/containment.sh' check '$attacker_sim_ip'"

# Feed 5 events (breaches threshold of 5)
input_stream_5=""
for i in {1..5}; do
    input_stream_5="${input_stream_5}${now_ts}|sshd|${attacker_sim_ip}|AUTH_FAILURE|Failed password attempt ${i}"$'\n'
done

printf "%s" "$input_stream_5" | "${PROJECT_ROOT}/bin/detector.sh" --stdin >/dev/null
assert_true "Threshold breached at 5th attempt and IP contained" "'${PROJECT_ROOT}/bin/containment.sh' check '$attacker_sim_ip'"

# Cleanup test ban
"${PROJECT_ROOT}/bin/containment.sh" unban "$attacker_sim_ip" >/dev/null
echo ""

# ------------------------------------------------------------------------------
# Test Suite 5: Forensic Timeline Dossier Compilation
# ------------------------------------------------------------------------------
echo -e "${CLR_YELLOW}[Test Group 5: Forensic Dossier Authoring]${CLR_RESET}"

test_inc="INC-AUTOTEST-$(date +%s)"
dossier_path="$("${PROJECT_ROOT}/bin/timeline.sh" compile "$test_inc" "198.51.100.77" "WEB_EXPLOIT_SCAN" "HIGH" 3 "Automated web scanner detected" | tail -n 1)"

assert_true "Markdown dossier file exists" "[[ -f '$dossier_path' ]]"
assert_true "Markdown header contains Incident ID" "grep -q '$test_inc' '$dossier_path'"
assert_true "Markdown dossier specifies CONTAINED status" "grep -q 'CONTAINED' '$dossier_path'"
assert_true "JSON dossier file exists" "[[ -f '${SENTINEL_INCIDENT_DIR}/${test_inc}.json' ]]"
assert_true "JSON dossier valid structure" "grep -q '\"incident_id\": \"$test_inc\"' '${SENTINEL_INCIDENT_DIR}/${test_inc}.json'"
echo ""

# ------------------------------------------------------------------------------
# Test Suite 6: Sentinel Master CLI Integration
# ------------------------------------------------------------------------------
echo -e "${CLR_YELLOW}[Test Group 6: Sentinel Master CLI Subcommands]${CLR_RESET}"

assert_true "sentinel.sh status runs without error" "'${PROJECT_ROOT}/bin/sentinel.sh' status >/dev/null"
assert_true "sentinel.sh rules runs without error" "'${PROJECT_ROOT}/bin/sentinel.sh' rules >/dev/null"
assert_true "sentinel.sh whitelist runs without error" "'${PROJECT_ROOT}/bin/sentinel.sh' whitelist >/dev/null"
echo ""

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
echo -e "${CLR_CYAN}======================================================================${CLR_RESET}"
echo -e "   Total Tests:  ${TOTAL_TESTS}"
echo -e "   ${CLR_GREEN}Passed Tests: ${PASSED_TESTS}${CLR_RESET}"
if (( FAILED_TESTS > 0 )); then
    echo -e "   ${CLR_RED}Failed Tests: ${FAILED_TESTS}${CLR_RESET}"
    echo -e "${CLR_RED}Phase 1 verification FAILED.${CLR_RESET}"
    exit 1
else
    echo -e "   ${CLR_GREEN}Failed Tests: 0${CLR_RESET}"
    echo -e "${CLR_GREEN}Phase 1 verification PASSED! All systems operational.${CLR_RESET}"
fi
echo -e "${CLR_CYAN}======================================================================${CLR_RESET}"
