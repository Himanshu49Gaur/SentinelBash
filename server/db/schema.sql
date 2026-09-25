-- ==============================================================================
-- SentinelBash - Master SQLite3 Production Schema
-- ==============================================================================
PRAGMA foreign_keys = ON;

-- 1. Table: users
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('ADMIN', 'ANALYST', 'AUDITOR', 'AUTOMATION_DAEMON')),
    api_key_hash TEXT UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    last_login_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_api_key_hash ON users(api_key_hash);

-- 2. Table: sessions
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    ip_address TEXT NOT NULL,
    user_agent TEXT,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(expires_at, revoked_at);

-- 3. Table: detection_rules
CREATE TABLE IF NOT EXISTS detection_rules (
    id TEXT PRIMARY KEY,
    rule_name TEXT NOT NULL UNIQUE,
    service_target TEXT NOT NULL,
    regex_pattern TEXT NOT NULL,
    threshold_count INTEGER NOT NULL DEFAULT 5,
    window_seconds INTEGER NOT NULL DEFAULT 60,
    default_ban_seconds INTEGER NOT NULL DEFAULT 3600,
    severity TEXT NOT NULL CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    is_enabled BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 4. Table: incidents
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    source_ip TEXT NOT NULL,
    threat_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    trigger_count INTEGER NOT NULL,
    window_duration_sec INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN (
        'CONTAINED',
        'EXPIRED',
        'MANUALLY_RELEASED',
        'WHITELIST_BYPASS'
    )),
    firewall_rule TEXT,
    ban_duration_sec INTEGER NOT NULL DEFAULT 3600,
    expires_at DATETIME,
    report_path TEXT NOT NULL,
    rule_id TEXT,
    released_by_user_id TEXT,
    released_at DATETIME,
    release_reason TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (rule_id) REFERENCES detection_rules(id) ON DELETE SET NULL,
    FOREIGN KEY (released_by_user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_incidents_source_ip ON incidents(source_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_active_bans ON incidents(status, expires_at) 
    WHERE status = 'CONTAINED';

-- 5. Table: incident_events
CREATE TABLE IF NOT EXISTS incident_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    event_timestamp DATETIME NOT NULL,
    service TEXT NOT NULL,
    raw_log TEXT NOT NULL,
    parsed_details TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_incident_events_rel ON incident_events(incident_id, event_timestamp);

-- 6. Table: firewall_rules
CREATE TABLE IF NOT EXISTS firewall_rules (
    id TEXT PRIMARY KEY,
    incident_id TEXT,
    target_ip TEXT NOT NULL,
    chain TEXT NOT NULL DEFAULT 'INPUT',
    action TEXT NOT NULL DEFAULT 'DROP',
    rule_comment_tag TEXT NOT NULL UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    removed_at DATETIME,
    removal_actor TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_firewall_ip ON firewall_rules(target_ip);
CREATE INDEX IF NOT EXISTS idx_firewall_active ON firewall_rules(is_active, expires_at);

-- 7. Table: whitelist_entries
CREATE TABLE IF NOT EXISTS whitelist_entries (
    id TEXT PRIMARY KEY,
    cidr_or_ip TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL,
    added_by_user_id TEXT,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    notes TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (added_by_user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_whitelist_active ON whitelist_entries(is_active);

-- 8. Table: notification_channels
CREATE TABLE IF NOT EXISTS notification_channels (
    id TEXT PRIMARY KEY,
    channel_name TEXT NOT NULL,
    channel_type TEXT NOT NULL CHECK(channel_type IN ('SLACK_WEBHOOK', 'TEAMS_WEBHOOK', 'EMAIL_SMTP', 'DISCORD_WEBHOOK')),
    webhook_url_encrypted TEXT NOT NULL,
    min_severity TEXT NOT NULL DEFAULT 'HIGH',
    is_enabled BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 9. Table: notifications_log
CREATE TABLE IF NOT EXISTS notifications_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    channel_id TEXT NOT NULL,
    dispatched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status_code INTEGER,
    error_message TEXT,
    payload_snapshot TEXT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    FOREIGN KEY (channel_id) REFERENCES notification_channels(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_notifications_incident ON notifications_log(incident_id);

-- 10. Table: audit_logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor_user_id TEXT,
    actor_role TEXT NOT NULL,
    action TEXT NOT NULL,
    target_entity TEXT NOT NULL,
    target_id TEXT,
    ip_address TEXT,
    change_summary TEXT NOT NULL,
    state_delta_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_logs(target_entity, target_id);
