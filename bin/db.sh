#!/usr/bin/env bash
# ==============================================================================
# SentinelBash - SQLite Database Bridge for Bash Engine
# ==============================================================================
set -euo pipefail

CURRENT_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${CURRENT_SCRIPT_DIR}/common.sh"
load_config
init_sentinel_dirs

SENTINEL_DB_FILE="${SENTINEL_ROOT_DIR}/data/sentinel.db"

# Execute SQL statement using sqlite3 CLI or Python fallback
execute_sql() {
    local sql="$1"
    if command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 -batch -bail "${SENTINEL_DB_FILE}" "$sql"
    else
        python -c "
import sqlite3, sys
conn = sqlite3.connect(r'${SENTINEL_DB_FILE}', timeout=10.0)
conn.execute('PRAGMA foreign_keys = ON;')
cursor = conn.cursor()
cursor.executescript(sys.argv[1])
conn.commit()
conn.close()
" "$sql"
    fi
}

# Query SQL and print output
query_sql() {
    local sql="$1"
    if command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 -header -column "${SENTINEL_DB_FILE}" "$sql"
    else
        python -c "
import sqlite3, sys
conn = sqlite3.connect(r'${SENTINEL_DB_FILE}', timeout=10.0)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()
cursor.execute(sys.argv[1])
rows = cursor.fetchall()
if rows:
    headers = rows[0].keys()
    print(' | '.join(headers))
    print('-' * 60)
    for r in rows:
        print(' | '.join(str(r[h]) for h in headers))
conn.close()
" "$sql"
    fi
}

# Insert a new incident record
insert_incident() {
    local inc_id="$1"
    local ip="$2"
    local vector="$3"
    local severity="$4"
    local count="${5:-1}"
    local status="${6:-CONTAINED}"
    local report_path="${7:-}"
    local fw_rule="${8:-iptables -I INPUT -s $ip -j DROP}"

    local sql="
INSERT INTO incidents (
    id, source_ip, threat_type, severity, trigger_count, 
    window_duration_sec, status, firewall_rule, ban_duration_sec, 
    expires_at, report_path
) VALUES (
    '${inc_id}', '${ip}', '${vector}', '${severity}', ${count}, 
    60, '${status}', '${fw_rule}', 3600, 
    datetime('now', '+3600 seconds'), '${report_path}'
) ON CONFLICT(id) DO UPDATE SET
    trigger_count = excluded.trigger_count,
    status = excluded.status;
"
    execute_sql "$sql"
}

# Insert an event associated with an incident
insert_incident_event() {
    local inc_id="$1"
    local service="$2"
    local raw_log="$3"
    local parsed="${4:-}"

    # Escape single quotes in raw log
    local clean_raw="${raw_log//\'/\'\'}"
    local clean_parsed="${parsed//\'/\'\'}"

    local sql="
INSERT INTO incident_events (
    incident_id, event_timestamp, service, raw_log, parsed_details
) VALUES (
    '${inc_id}', CURRENT_TIMESTAMP, '${service}', '${clean_raw}', '${clean_parsed}'
);
"
    execute_sql "$sql"
}

# Insert an applied firewall rule
insert_firewall_rule() {
    local fw_id="$1"
    local inc_id="$2"
    local ip="$3"
    local comment_tag="$4"
    local action="${5:-DROP}"

    local sql="
INSERT INTO firewall_rules (
    id, incident_id, target_ip, chain, action, rule_comment_tag, is_active, expires_at
) VALUES (
    '${fw_id}', '${inc_id}', '${ip}', 'INPUT', '${action}', '${comment_tag}', 1, datetime('now', '+3600 seconds')
) ON CONFLICT(rule_comment_tag) DO UPDATE SET
    is_active = 1,
    applied_at = CURRENT_TIMESTAMP;
"
    execute_sql "$sql"
}

# Update incident status upon manual release or expiration
update_incident_status() {
    local inc_id="$1"
    local status="$2"
    local reason="${3:-Operator or automated action}"

    local sql="
UPDATE incidents 
SET status = '${status}',
    released_at = CURRENT_TIMESTAMP,
    release_reason = '${reason}'
WHERE id = '${inc_id}';
"
    execute_sql "$sql"
}

# Deactivate firewall rule for an IP
deactivate_firewall_rule() {
    local ip="$1"
    local actor="${2:-MANUAL_OPERATOR}"

    local sql="
UPDATE firewall_rules
SET is_active = 0,
    removed_at = CURRENT_TIMESTAMP,
    removal_actor = '${actor}'
WHERE target_ip = '${ip}' AND is_active = 1;

UPDATE incidents
SET status = 'MANUALLY_RELEASED',
    released_at = CURRENT_TIMESTAMP,
    release_reason = 'Containment revoked for ${ip}'
WHERE source_ip = '${ip}' AND status = 'CONTAINED';
"
    execute_sql "$sql"
}

# Show database summary stats
show_db_stats() {
    echo -e "${CLR_CYAN}=== SentinelBash Database Telemetry Stats ===${CLR_RESET}"
    query_sql "
SELECT 
    (SELECT COUNT(*) FROM users) AS total_users,
    (SELECT COUNT(*) FROM detection_rules) AS active_rules,
    (SELECT COUNT(*) FROM whitelist_entries) AS whitelist_rules,
    (SELECT COUNT(*) FROM incidents) AS total_incidents,
    (SELECT COUNT(*) FROM incidents WHERE status = 'CONTAINED') AS active_bans,
    (SELECT COUNT(*) FROM audit_logs) AS audit_entries;
"
}

# CLI Dispatcher
case "${1:-}" in
    insert-incident)
        shift
        insert_incident "$@"
        ;;
    insert-event)
        shift
        insert_incident_event "$@"
        ;;
    insert-firewall)
        shift
        insert_firewall_rule "$@"
        ;;
    update-incident)
        shift
        update_incident_status "$@"
        ;;
    deactivate-firewall)
        shift
        deactivate_firewall_rule "$@"
        ;;
    query)
        shift
        query_sql "$*"
        ;;
    stats)
        show_db_stats
        ;;
    *)
        echo "Usage: $0 {insert-incident | insert-event | insert-firewall | update-incident | deactivate-firewall | query <sql> | stats}"
        exit 1
        ;;
esac

