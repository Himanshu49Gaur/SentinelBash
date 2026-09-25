"""
SentinelBash - Database Initializer & Migration Seeder
Executes schema.sql and seeds initial detection rules, admin user, and whitelist.
"""

import os
import sys
import hashlib
import uuid
from datetime import datetime

# Add server directory to path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
SERVER_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))

if SERVER_DIR not in sys.path:
    sys.path.insert(0, SERVER_DIR)

from db.database import get_db_connection, get_db_path


def hash_password(password: str, salt: str = "sentinel_salt_2026") -> str:
    """Generates a secure salted SHA-256 hash for password authentication."""
    salted = f"{salt}:{password}"
    return f"sha256${salt}${hashlib.sha256(salted.encode('utf-8')).hexdigest()}"


def hash_api_key(api_key: str) -> str:
    """Computes SHA-256 digest of an API key for indexed lookup."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def init_database() -> None:
    schema_path = os.path.join(CURRENT_DIR, "schema.sql")
    if not os.path.exists(schema_path):
        raise FileNotFoundError(f"Schema file not found at {schema_path}")

    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    db_path = get_db_path()
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    print(f"[*] Initializing database at: {db_path}")

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.executescript(schema_sql)

        # 1. Seed Detection Rules
        rules = [
            (
                "RULE_SSH_BRUTE_FORCE",
                "SSH Brute Force Velocity",
                "auth.log",
                r"Failed password|Invalid user",
                5,
                60,
                3600,
                "CRITICAL",
                1,
            ),
            (
                "RULE_WEB_PROBE",
                "Web Reconnaissance & Path Probes",
                "nginx/access.log",
                r"\.\./|\.\.\\|/etc/passwd|\.env|\.git|phpmyadmin",
                3,
                45,
                3600,
                "HIGH",
                1,
            ),
            (
                "RULE_SUDO_ABUSE",
                "Privilege Escalation Violations",
                "syslog",
                r"incorrect password|authentication failure|NOT in sudoers",
                3,
                60,
                7200,
                "CRITICAL",
                1,
            ),
        ]

        cursor.executemany(
            """
            INSERT INTO detection_rules (
                id, rule_name, service_target, regex_pattern, 
                threshold_count, window_seconds, default_ban_seconds, 
                severity, is_enabled
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                rule_name=excluded.rule_name,
                threshold_count=excluded.threshold_count,
                window_seconds=excluded.window_seconds,
                severity=excluded.severity,
                updated_at=CURRENT_TIMESTAMP;
            """,
            rules,
        )
        print(f"[+] Seeded {len(rules)} detection rules.")

        # 2. Seed Default Admin User
        admin_id = "usr_01ADMIN000000000000000001"
        admin_user = "admin"
        admin_email = "admin@sentinel.secops"
        admin_pass_hash = hash_password("AdminSentinel2026!")
        admin_api_key = "snt_live_bootstrap_master_admin_key_2026"
        admin_api_key_hash = hash_api_key(admin_api_key)

        cursor.execute(
            """
            INSERT INTO users (
                id, username, email, password_hash, role, api_key_hash, is_active
            ) VALUES (?, ?, ?, ?, 'ADMIN', ?, 1)
            ON CONFLICT(username) DO UPDATE SET
                password_hash=excluded.password_hash,
                api_key_hash=excluded.api_key_hash,
                updated_at=CURRENT_TIMESTAMP;
            """,
            (admin_id, admin_user, admin_email, admin_pass_hash, admin_api_key_hash),
        )
        print("[+] Seeded default administrator account: 'admin'.")

        # 3. Seed Default Notification Channels
        channels = [
            (
                "CHAN_SLACK_DEFAULT",
                "#soc-critical-alerts",
                "SLACK_WEBHOOK",
                "https://hooks.slack.com/services/MOCK/B00000000/mock_webhook_token",
                "HIGH",
                1,
            ),
            (
                "CHAN_DISCORD_DEFAULT",
                "#secops-feed",
                "DISCORD_WEBHOOK",
                "https://discord.com/api/webhooks/MOCK/mock_token",
                "HIGH",
                1,
            ),
        ]

        cursor.executemany(
            """
            INSERT INTO notification_channels (
                id, channel_name, channel_type, webhook_url_encrypted, min_severity, is_enabled
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                channel_name=excluded.channel_name,
                updated_at=CURRENT_TIMESTAMP;
            """,
            channels,
        )
        print(f"[+] Seeded {len(channels)} notification channels.")

        # 4. Seed Whitelist Entries from config/whitelist.conf
        whitelist_path = os.path.join(PROJECT_ROOT, "config", "whitelist.conf")
        seeded_wl_count = 0
        if os.path.exists(whitelist_path):
            with open(whitelist_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    entry = line.split()[0]
                    wl_id = f"WL-{hashlib.md5(entry.encode()).hexdigest()[:8].upper()}"
                    cursor.execute(
                        """
                        INSERT INTO whitelist_entries (id, cidr_or_ip, label, is_active, notes)
                        VALUES (?, ?, 'Core Protected Subnet', 1, 'Imported from whitelist.conf')
                        ON CONFLICT(cidr_or_ip) DO NOTHING;
                        """,
                        (wl_id, entry),
                    )
                    seeded_wl_count += 1
            print(f"[+] Seeded {seeded_wl_count} whitelist entries from whitelist.conf.")

        # 5. Insert Initial Audit Log Record
        cursor.execute(
            """
            INSERT INTO audit_logs (
                actor_user_id, actor_role, action, target_entity, target_id, change_summary
            ) VALUES (?, 'ADMIN', 'SYSTEM_INIT', 'DATABASE', 'sentinel.db', 'Initialized SQLite schema and seed records');
            """,
            (admin_id,),
        )

    print("[*] Database migration and seeding COMPLETED successfully.")


if __name__ == "__main__":
    init_database()
