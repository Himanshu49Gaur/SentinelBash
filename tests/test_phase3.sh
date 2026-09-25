#!/usr/bin/env bash
# ==============================================================================
# SentinelBash - Phase 3 Automated Verification & Test Suite
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

echo -e "${CLR_CYAN}======================================================================${CLR_RESET}"
echo -e "${CLR_WHITE}   SentinelBash Phase 3: REST API & Gateway Test Suite   ${CLR_RESET}"
echo -e "${CLR_CYAN}======================================================================${CLR_RESET}"
echo ""

# Python virtual environment binary resolver
PYTHON_BIN="${PROJECT_ROOT}/.venv/Scripts/python.exe"
if [[ ! -f "$PYTHON_BIN" ]]; then
    PYTHON_BIN="python"
fi

# ------------------------------------------------------------------------------
# Test Suite 1: Python FastAPI & RBAC Unit Tests
# ------------------------------------------------------------------------------
echo -e "${CLR_YELLOW}[Test Group 1: FastAPI Endpoints & RBAC Validation]${CLR_RESET}"
assert_true "FastAPI TestClient suite passes (test_api.py)" "'$PYTHON_BIN' '${PROJECT_ROOT}/tests/test_api.py' >/dev/null 2>&1"
echo ""

# ------------------------------------------------------------------------------
# Test Suite 2: Live Uvicorn Server & Network Endpoint Checks
# ------------------------------------------------------------------------------
echo -e "${CLR_YELLOW}[Test Group 2: Live Server & SSE Streaming Gateway]${CLR_RESET}"

TEST_PORT=8089
SERVER_PID_FILE="${SENTINEL_RUN_DIR}/api_test_server.pid"

# Launch Uvicorn in background
log_info "Spinning up live FastAPI test instance on 127.0.0.1:${TEST_PORT}..."
"$PYTHON_BIN" -m uvicorn server.main:app --host 127.0.0.1 --port "$TEST_PORT" > "${SENTINEL_LOG_DIR}/api_test_server.log" 2>&1 &
SERVER_PID=$!
echo "$SERVER_PID" > "$SERVER_PID_FILE"

# Wait for server ready
sleep 2

# Check if server is running
assert_true "FastAPI Uvicorn server started" "kill -0 '$SERVER_PID' 2>/dev/null"

# Test /docs Swagger OpenAPI accessibility
docs_code="$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${TEST_PORT}/docs" || echo "000")"
assert_true "Swagger OpenAPI documentation reachable (/docs)" "[[ '$docs_code' == '200' ]]"

# Test /api/v1/health live response
health_json="$(curl -s "http://127.0.0.1:${TEST_PORT}/api/v1/health" || echo "")"
assert_true "Health endpoint returns valid status" "[[ '$health_json' =~ 'status' && '$health_json' =~ 'database' ]]"

# Test Server-Sent Events (SSE) log stream handshake
sse_handshake="$(curl -s -N --max-time 2 "http://127.0.0.1:${TEST_PORT}/api/v1/stream/logs" 2>/dev/null | head -n 4 || echo "")"
assert_true "SSE stream handshake established" "[[ '$sse_handshake' =~ 'event: handshake' || '$sse_handshake' =~ 'CONNECTED' ]]"

# Gracefully terminate live server
log_info "Shutting down live FastAPI test instance..."
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
rm -f "$SERVER_PID_FILE"
assert_true "Server terminated cleanly" "! kill -0 '$SERVER_PID' 2>/dev/null"
echo ""

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
echo -e "${CLR_CYAN}======================================================================${CLR_RESET}"
echo -e "   Total Tests:  ${TOTAL_TESTS}"
echo -e "   ${CLR_GREEN}Passed Tests: ${PASSED_TESTS}${CLR_RESET}"
if (( FAILED_TESTS > 0 )); then
    echo -e "   ${CLR_RED}Failed Tests: ${FAILED_TESTS}${CLR_RESET}"
    echo -e "${CLR_RED}Phase 3 verification FAILED.${CLR_RESET}"
    exit 1
else
    echo -e "   ${CLR_GREEN}Failed Tests: 0${CLR_RESET}"
    echo -e "${CLR_GREEN}Phase 3 verification PASSED! All systems operational.${CLR_RESET}"
fi
echo -e "${CLR_CYAN}======================================================================${CLR_RESET}"
