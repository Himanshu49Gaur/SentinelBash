#!/usr/bin/env bash
# ==============================================================================
# SentinelBash - Multi-Channel Alert Dispatcher & Notification Spooler
# ==============================================================================
set -euo pipefail

CURRENT_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${CURRENT_SCRIPT_DIR}/common.sh"
load_config
init_sentinel_dirs

ALERT_SPOOL_FILE="${SENTINEL_LOG_DIR}/alert_spool.log"

# Generate Slack Block Kit JSON Payload
build_slack_payload() {
    local inc_id="$1"
    local ip="$2"
    local vector="$3"
    local severity="$4"
    local summary="$5"
    local count="${6:-1}"
    local host
    host="$(hostname 2>/dev/null || echo "linux-host")"
    local timestamp_iso
    timestamp_iso="$(get_timestamp)"

    # Severity color
    local color="#E11D48" # CRITICAL
    local icon="🚨"
    case "$severity" in
        HIGH)
            color="#F97316"
            icon="⚠️"
            ;;
        MEDIUM)
            color="#EAB308"
            icon="⚡"
            ;;
        LOW)
            color="#3B82F6"
            icon="ℹ️"
            ;;
    esac

    cat <<EOF
{
  "attachments": [
    {
      "color": "${color}",
      "blocks": [
        {
          "type": "header",
          "text": {
            "type": "plain_text",
            "text": "${icon} SentinelBash Security Alert: ${vector}",
            "emoji": true
          }
        },
        {
          "type": "section",
          "fields": [
            {
              "type": "mrkdwn",
              "text": "*Incident ID:*\n\`${inc_id}\`"
            },
            {
              "type": "mrkdwn",
              "text": "*Severity:*\n*${severity}*"
            },
            {
              "type": "mrkdwn",
              "text": "*Attacker Source IP:*\n\`${ip}\`"
            },
            {
              "type": "mrkdwn",
              "text": "*Breach Events:*\n${count} violations"
            },
            {
              "type": "mrkdwn",
              "text": "*Target Host:*\n\`${host}\`"
            },
            {
              "type": "mrkdwn",
              "text": "*Action Taken:*\n\`Netfilter DROP (Quarantined)\`"
            }
          ]
        },
        {
          "type": "section",
          "text": {
            "type": "mrkdwn",
            "text": "*Summary:* ${summary}\n*Timestamp:* \`${timestamp_iso}\`"
          }
        },
        {
          "type": "context",
          "elements": [
            {
              "type": "mrkdwn",
              "text": "🛡️ Automated SOC Containment by SentinelBash v1.0.0"
            }
          ]
        }
      ]
    }
  ]
}
EOF
}

# Generate Discord Embed JSON Payload
build_discord_payload() {
    local inc_id="$1"
    local ip="$2"
    local vector="$3"
    local severity="$4"
    local summary="$5"
    local count="${6:-1}"
    local host
    host="$(hostname 2>/dev/null || echo "linux-host")"
    local timestamp_iso
    timestamp_iso="$(get_timestamp)"

    # Decimal color for Discord embed
    local color=14752072 # Red for CRITICAL
    case "$severity" in
        HIGH)   color=16348182 ;; # Orange
        MEDIUM) color=15381256 ;; # Yellow
        LOW)    color=3899894  ;; # Blue
    esac

    cat <<EOF
{
  "username": "SentinelBash SOC",
  "embeds": [
    {
      "title": "🚨 Security Incident: ${vector}",
      "description": "${summary}",
      "color": ${color},
      "fields": [
        {"name": "Incident ID", "value": "\`${inc_id}\`", "inline": true},
        {"name": "Severity", "value": "**${severity}**", "inline": true},
        {"name": "Attacker IP", "value": "\`${ip}\`", "inline": true},
        {"name": "Violations", "value": "${count}", "inline": true},
        {"name": "Target Host", "value": "\`${host}\`", "inline": true},
        {"name": "Containment", "value": "Netfilter DROP (Active)", "inline": true}
      ],
      "footer": {"text": "SentinelBash SOAR Engine"},
      "timestamp": "${timestamp_iso}"
    }
  ]
}
EOF
}

# Spool an alert to local disk for offline retry
spool_alert() {
    local channel_type="$1"
    local webhook_url="$2"
    local payload="$3"
    local reason="${4:-Connection failure}"
    local timestamp_iso
    timestamp_iso="$(get_timestamp)"

    # Base64 encode payload to store as single line
    local b64_payload
    b64_payload="$(printf "%s" "$payload" | base64 -w 0 2>/dev/null || printf "%s" "$payload" | base64 2>/dev/null | tr -d '\n')"

    echo "${timestamp_iso}|${channel_type}|${webhook_url}|${b64_payload}|1|${reason}" >> "$ALERT_SPOOL_FILE"
    log_warn "Alert spooled to disk for offline delivery: ${ALERT_SPOOL_FILE} [Reason: ${reason}]"
}

# Transmit HTTP webhook with timeout and retry handling
transmit_webhook() {
    local channel_id="$1"
    local channel_type="$2"
    local webhook_url="$3"
    local payload="$4"
    local inc_id="$5"

    log_info "Dispatching alert to ${channel_type}..."

    # If mock webhook, simulate successful dispatch and log
    if [[ "$webhook_url" == *"mock"* || "$webhook_url" == *"example.com"* || "$webhook_url" == "" ]]; then
        log_info "[MOCK WEBHOOK] Simulated successful dispatch to ${channel_type} [Incident: ${inc_id}]"
        
        # Log to database via db.sh if available
        if [[ -f "${CURRENT_SCRIPT_DIR}/db.sh" ]]; then
            local clean_payload="${payload//\'/\'\'}"
            "${CURRENT_SCRIPT_DIR}/db.sh" query "
INSERT INTO notifications_log (incident_id, channel_id, status_code, payload_snapshot)
VALUES ('${inc_id}', '${channel_id}', 200, '${clean_payload}');
" >/dev/null 2>&1 || true
        fi
        return 0
    fi

    # Perform real cURL post with 4s connection timeout
    local http_response
    local http_code
    http_code="$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        --connect-timeout 4 \
        --max-time 8 \
        -d "$payload" \
        "$webhook_url" 2>/dev/null || echo "000")"

    if [[ "$http_code" =~ ^(200|204)$ ]]; then
        log_success "Alert successfully delivered to ${channel_type} [HTTP: ${http_code}]."
        if [[ -f "${CURRENT_SCRIPT_DIR}/db.sh" ]]; then
            local clean_payload="${payload//\'/\'\'}"
            "${CURRENT_SCRIPT_DIR}/db.sh" query "
INSERT INTO notifications_log (incident_id, channel_id, status_code, payload_snapshot)
VALUES ('${inc_id}', '${channel_id}', ${http_code}, '${clean_payload}');
" >/dev/null 2>&1 || true
        fi
        return 0
    else
        log_warn "Failed to deliver alert to ${channel_type} [HTTP: ${http_code}]. Spooling for retry."
        spool_alert "$channel_type" "$webhook_url" "$payload" "HTTP error ${http_code}"
        if [[ -f "${CURRENT_SCRIPT_DIR}/db.sh" ]]; then
            local clean_payload="${payload//\'/\'\'}"
            "${CURRENT_SCRIPT_DIR}/db.sh" query "
INSERT INTO notifications_log (incident_id, channel_id, status_code, error_message, payload_snapshot)
VALUES ('${inc_id}', '${channel_id}', ${http_code}, 'HTTP response ${http_code}', '${clean_payload}');
" >/dev/null 2>&1 || true
        fi
        return 1
    fi
}

# Main dispatch coordinator
dispatch_incident_alert() {
    local inc_id="$1"
    local ip="$2"
    local vector="$3"
    local severity="${4:-HIGH}"
    local summary="${5:-Security threshold violation detected. Attacker contained.}"
    local count="${6:-1}"

    # Build Slack payload
    local slack_payload
    slack_payload="$(build_slack_payload "$inc_id" "$ip" "$vector" "$severity" "$summary" "$count")"

    # Query active notification channels from database or use defaults
    local slack_url="https://hooks.slack.com/services/MOCK/B00000000/mock_webhook_token"
    if [[ -f "${CURRENT_SCRIPT_DIR}/db.sh" ]]; then
        local db_url
        db_url="$("${CURRENT_SCRIPT_DIR}/db.sh" query "SELECT webhook_url_encrypted FROM notification_channels WHERE channel_type='SLACK_WEBHOOK' AND is_enabled=1 LIMIT 1;" 2>/dev/null | tail -n 1 | tr -d ' ' || echo "")"
        if [[ -n "$db_url" && "$db_url" != *"webhook_url_encrypted"* ]]; then
            slack_url="$db_url"
        fi
    fi

    # Dispatch to Slack
    transmit_webhook "CHAN_SLACK_DEFAULT" "SLACK_WEBHOOK" "$slack_url" "$slack_payload" "$inc_id" || true
}

# Flush spooled offline alerts
flush_spool() {
    if [[ ! -s "$ALERT_SPOOL_FILE" ]]; then
        log_info "Alert spool is empty. No offline alerts pending."
        return 0
    fi

    log_info "Flushing offline alert spool..."
    local tmp_spool="${ALERT_SPOOL_FILE}.tmp.$$"
    touch "$tmp_spool"

    while IFS='|' read -r timestamp channel_type url b64_payload retry_count last_err || [[ -n "$timestamp" ]]; do
        [[ -z "$b64_payload" ]] && continue
        local payload
        payload="$(printf "%s" "$b64_payload" | base64 -d 2>/dev/null || printf "%s" "$b64_payload" | base64 --decode 2>/dev/null || echo "")"

        if [[ -z "$payload" ]]; then
            continue
        fi

        log_info "Retrying delivery for spooled alert (${channel_type})..."
        if [[ "$url" == *"mock"* ]]; then
            log_info "[MOCK] Cleared mock spooled alert."
            continue
        fi

        local http_code
        http_code="$(curl -s -o /dev/null -w "%{http_code}" -X POST \
            -H "Content-Type: application/json" \
            --connect-timeout 4 \
            --max-time 8 \
            -d "$payload" \
            "$url" 2>/dev/null || echo "000")"

        if [[ "$http_code" =~ ^(200|204)$ ]]; then
            log_success "Spooled alert successfully re-transmitted!"
        else
            local next_retry=$(( retry_count + 1 ))
            if (( next_retry <= 5 )); then
                log_warn "Retry failed (HTTP ${http_code}). Re-queueing [Attempt: ${next_retry}/5]."
                echo "${timestamp}|${channel_type}|${url}|${b64_payload}|${next_retry}|HTTP ${http_code}" >> "$tmp_spool"
            else
                log_err "Max retries (5) exceeded for spooled alert. Discarding."
            fi
        fi
    done < "$ALERT_SPOOL_FILE"

    mv -f "$tmp_spool" "$ALERT_SPOOL_FILE"
    log_success "Spool flush routine complete."
}

# View current spool
view_spool() {
    if [[ ! -s "$ALERT_SPOOL_FILE" ]]; then
        echo "Alert spool is clean. Zero pending notifications."
        return 0
    fi

    echo -e "${CLR_CYAN}=== Pending Spooled Notifications ===${CLR_RESET}"
    while IFS='|' read -r timestamp channel_type url b64_payload retry_count last_err || [[ -n "$timestamp" ]]; do
        [[ -z "$timestamp" ]] && continue
        echo "  [${timestamp}] Type: ${channel_type} | Retries: ${retry_count} | Last Error: ${last_err}"
    done < "$ALERT_SPOOL_FILE"
}

# CLI Interface
case "${1:-}" in
    dispatch)
        shift
        dispatch_incident_alert "$@"
        ;;
    build-slack)
        shift
        build_slack_payload "$@"
        ;;
    build-discord)
        shift
        build_discord_payload "$@"
        ;;
    flush-spool)
        flush_spool
        ;;
    view-spool)
        view_spool
        ;;
    *)
        echo "Usage: $0 {dispatch <INC_ID> <IP> <VECTOR> [SEVERITY] [SUMMARY] [COUNT] | build-slack ... | build-discord ... | flush-spool | view-spool}"
        exit 1
        ;;
esac
