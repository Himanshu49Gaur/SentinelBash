#!/usr/bin/env bash
# ==============================================================================
# SentinelBash - Phase 2 Automated Verification & Test Suite
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
echo -e "${CLR_WHITE}   SentinelBash Phase 2: Database & Notifier Test Suite   ${CLR_RESET}"
echo -e "${CLR_CYAN}======================================================================${CLR_RESET}"
echo ""

# Ensure database is initialized
python "${PROJECT_ROOT}/server/db/init_db.py" >/dev/null

# ------------------------------------------------------------------------------
# Test Suite 1: Python Database Schema Unit Tests
# ------------------------------------------------------------------------------
echo -e "${CLR_YELLOW}[Test Group 1: Python Database & DAO Suite]${CLR_RESET}"
assert_true "Python unittest suite passes (test_database.py)" "python '${PROJECT_ROOT}/tests/test_database.py' >/dev/null 2>&1"
echo ""

# ------------------------------------------------------------------------------
# Test Suite 2: Bash SQLite Bridge (db.sh) Operations
# ------------------------------------------------------------------------------
echo -e "${CLR_YELLOW}[Test Group 2: Bash SQLite Interface (bin/db.sh)]${CLR_RESET}"

test_inc="INC-PHASE2-TEST-$$"
test_ip="198.51.100.80"

# 1. Insert Incident
"${PROJECT_ROOT}/bin/db.sh" insert-incident "$test_inc" "$test_ip" "SSH_BRUTE_FORCE" "CRITICAL" 5 "CONTAINED" "/tmp/test.md"
query_res="$("${PROJECT_ROOT}/bin/db.sh" query "SELECT id, source_ip, status FROM incidents WHERE id='${test_inc}';")"
assert_true "Incident inserted via db.sh" "[[ '$query_res' =~ $test_inc && '$query_res' =~ $test_ip ]]"

# 2. Insert Event
"${PROJECT_ROOT}/bin/db.sh" insert-event "$test_inc" "sshd" "Failed password for admin" '{"user":"admin"}'
ev_res="$("${PROJECT_ROOT}/bin/db.sh" query "SELECT incident_id, service FROM incident_events WHERE incident_id='${test_inc}';")"
assert_true "Incident event inserted via db.sh" "[[ '$ev_res' =~ $test_inc && '$ev_res' =~ sshd ]]"

# 3. Insert Firewall Rule
"${PROJECT_ROOT}/bin/db.sh" insert-firewall "FW-${test_inc}" "$test_inc" "$test_ip" "SENTINEL:${test_inc}" "DROP"
fw_res="$("${PROJECT_ROOT}/bin/db.sh" query "SELECT id, target_ip, is_active FROM firewall_rules WHERE target_ip='${test_ip}';")"
assert_true "Firewall rule active in SQLite" "[[ '$fw_res' =~ $test_ip && '$fw_res' =~ 1 ]]"

# 4. Deactivate Firewall Rule (Unban)
"${PROJECT_ROOT}/bin/db.sh" deactivate-firewall "$test_ip" "UNIT_TEST"
fw_deact="$("${PROJECT_ROOT}/bin/db.sh" query "SELECT is_active FROM firewall_rules WHERE target_ip='${test_ip}';")"
assert_true "Firewall rule marked inactive" "[[ '$fw_deact' =~ 0 ]]"
echo ""

# ------------------------------------------------------------------------------
# Test Suite 3: Multi-Channel Alert Payload Generation
# ------------------------------------------------------------------------------
echo -e "${CLR_YELLOW}[Test Group 3: Alert Formatter (Slack Block Kit & Discord)]${CLR_RESET}"

# 1. Slack Payload
slack_json="$("${PROJECT_ROOT}/bin/notifier.sh" build-slack "$test_inc" "$test_ip" "SSH_BRUTE_FORCE" "CRITICAL" "Brute force attack" 5)"
assert_true "Slack Block Kit header present" "[[ '$slack_json' =~ SentinelBash\ Security\ Alert ]]"
assert_true "Slack Block Kit color CRITICAL red" "[[ '$slack_json' =~ '#E11D48' ]]"
assert_true "Slack Block Kit fields present" "[[ '$slack_json' =~ Incident\ ID && '$slack_json' =~ Attacker\ Source\ IP ]]"

# 2. Discord Payload
discord_json="$("${PROJECT_ROOT}/bin/notifier.sh" build-discord "$test_inc" "$test_ip" "WEB_EXPLOIT_SCAN" "HIGH" "Path traversal" 3)"
assert_true "Discord embed title present" "[[ '$discord_json' =~ Security\ Incident:\ WEB_EXPLOIT_SCAN ]]"
assert_true "Discord embed color present" "[[ '$discord_json' =~ 16348182 ]]"
echo ""

# ------------------------------------------------------------------------------
# Test Suite 4: Dispatcher & Spooler Mechanics
# ------------------------------------------------------------------------------
echo -e "${CLR_YELLOW}[Test Group 4: Webhook Dispatching & Offline Spooling]${CLR_RESET}"

# 1. Simulated Dispatch & Notification Log
"${PROJECT_ROOT}/bin/notifier.sh" dispatch "$test_inc" "$test_ip" "SSH_BRUTE_FORCE" "CRITICAL" "Test dispatch" 5 >/dev/null
notif_res="$("${PROJECT_ROOT}/bin/db.sh" query "SELECT incident_id, status_code FROM notifications_log WHERE incident_id='${test_inc}';")"
assert_true "Notification logged to notifications_log table" "[[ '$notif_res' =~ $test_inc && '$notif_res' =~ 200 ]]"

# 2. Spool Flush Routine
assert_true "flush-spool runs cleanly" "'${PROJECT_ROOT}/bin/notifier.sh' flush-spool >/dev/null"
assert_true "view-spool displays clean status" "'${PROJECT_ROOT}/bin/notifier.sh' view-spool >/dev/null"
echo ""

# ------------------------------------------------------------------------------
# Test Suite 5: End-to-End Threat Detection -> SOAR -> DB -> Notifier Sync
# ------------------------------------------------------------------------------
echo -e "${CLR_YELLOW}[Test Group 5: Full Engine Threat-to-Database Sync]${CLR_RESET}"

e2e_ip="198.51.100.222"
now_ts="$(get_epoch)"

# Ensure clean slate for e2e_ip
"${PROJECT_ROOT}/bin/containment.sh" unban "$e2e_ip" >/dev/null 2>&1 || true

# Stream 5 failures into detector
e2e_stream=""
for i in {1..5}; do
    e2e_stream="${e2e_stream}${now_ts}|sshd|${e2e_ip}|AUTH_FAILURE|Failed password attempt ${i}"$'\n'
done

printf "%s" "$e2e_stream" | "${PROJECT_ROOT}/bin/detector.sh" --stdin >/dev/null

# 1. Verify containment state
assert_true "E2E attacker contained by firewall" "'${PROJECT_ROOT}/bin/containment.sh' check '$e2e_ip'"

# 2. Verify incident record in SQLite
db_inc="$("${PROJECT_ROOT}/bin/db.sh" query "SELECT id, source_ip, status FROM incidents WHERE source_ip='${e2e_ip}' AND status='CONTAINED';")"
assert_true "E2E incident persisted in SQLite" "[[ '$db_inc' =~ $e2e_ip && '$db_inc' =~ CONTAINED ]]"

# 3. Verify firewall rule in SQLite
db_fw="$("${PROJECT_ROOT}/bin/db.sh" query "SELECT target_ip, is_active FROM firewall_rules WHERE target_ip='${e2e_ip}' AND is_active=1;")"
assert_true "E2E firewall rule active in SQLite" "[[ '$db_fw' =~ $e2e_ip && '$db_fw' =~ 1 ]]"

# 4. Verify notification log in SQLite
db_notif="$("${PROJECT_ROOT}/bin/db.sh" query "SELECT n.status_code FROM notifications_log n JOIN incidents i ON n.incident_id=i.id WHERE i.source_ip='${e2e_ip}';")"
assert_true "E2E alert recorded in notifications_log" "[[ '$db_notif' =~ 200 ]]"

# Cleanup E2E ban
"${PROJECT_ROOT}/bin/containment.sh" unban "$e2e_ip" >/dev/null
echo ""

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
echo -e "${CLR_CYAN}======================================================================${CLR_RESET}"
echo -e "   Total Tests:  ${TOTAL_TESTS}"
echo -e "   ${CLR_GREEN}Passed Tests: ${PASSED_TESTS}${CLR_RESET}"
if (( FAILED_TESTS > 0 )); then
    echo -e "   ${CLR_RED}Failed Tests: ${FAILED_TESTS}${CLR_RESET}"
    echo -e "${CLR_RED}Phase 2 verification FAILED.${CLR_RESET}"
    exit 1
else
    echo -e "   ${CLR_GREEN}Failed Tests: 0${CLR_RESET}"
    echo -e "${CLR_GREEN}Phase 2 verification PASSED! All systems operational.${CLR_RESET}"
fi
echo -e "${CLR_CYAN}======================================================================${CLR_RESET}"
