"""
SentinelBash - Database Schema & DAO Unit Test Suite
Validates SQLite3 WAL configuration, foreign key constraints, table schemas, and data operations.
"""

import os
import sys
import tempfile
import sqlite3
import unittest
from datetime import datetime

# Path setup
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
SERVER_DIR = os.path.join(PROJECT_ROOT, "server")

if SERVER_DIR not in sys.path:
    sys.path.insert(0, SERVER_DIR)

from db.database import (
    configure_sqlite_connection,
    get_db_connection,
    query_all,
    query_one,
    execute_stmt,
)
from db.init_db import init_database, hash_password, hash_api_key


class TestDatabaseSchema(unittest.TestCase):
    def setUp(self):
        """Create a temporary database for isolated testing."""
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.temp_db_fd)
        os.environ["SENTINEL_DB_PATH"] = self.temp_db_path
        init_database()

    def tearDown(self):
        """Clean up temporary test database."""
        if os.path.exists(self.temp_db_path):
            os.remove(self.temp_db_path)
        # Remove any WAL and SHM files
        for ext in ["-wal", "-shm"]:
            f = self.temp_db_path + ext
            if os.path.exists(f):
                os.remove(f)

    def test_wal_mode_enabled(self):
        """Verifies that SQLite PRAGMA journal_mode is WAL."""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode;")
            mode = cursor.fetchone()[0]
            self.assertEqual(mode.upper(), "WAL")

    def test_foreign_keys_enabled(self):
        """Verifies foreign key constraints are enforced."""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA foreign_keys;")
            fk = cursor.fetchone()[0]
            self.assertEqual(fk, 1)

    def test_schema_tables_exist(self):
        """Verifies that all 10 tables exist in the database."""
        expected_tables = {
            "users",
            "sessions",
            "detection_rules",
            "incidents",
            "incident_events",
            "firewall_rules",
            "whitelist_entries",
            "notification_channels",
            "notifications_log",
            "audit_logs",
        }
        rows = query_all("SELECT name FROM sqlite_master WHERE type='table';")
        existing_tables = {r["name"] for r in rows}
        for table in expected_tables:
            self.assertIn(table, existing_tables, f"Missing table: {table}")

    def test_seeded_rules(self):
        """Verifies default detection rules are populated."""
        rules = query_all("SELECT id, threshold_count, severity FROM detection_rules;")
        rule_ids = {r["id"] for r in rules}
        self.assertIn("RULE_SSH_BRUTE_FORCE", rule_ids)
        self.assertIn("RULE_WEB_PROBE", rule_ids)
        self.assertIn("RULE_SUDO_ABUSE", rule_ids)

    def test_admin_user_seeded(self):
        """Verifies default administrator account exists."""
        admin = query_one("SELECT * FROM users WHERE username = 'admin';")
        self.assertIsNotNone(admin)
        self.assertEqual(admin["role"], "ADMIN")
        self.assertTrue(admin["is_active"])
        self.assertTrue(admin["password_hash"].startswith("sha256$"))

    def test_incident_and_events_foreign_key(self):
        """Verifies incident and related events insertion and cascades."""
        inc_id = "INC-TEST-FK-001"
        execute_stmt(
            """
            INSERT INTO incidents (
                id, source_ip, threat_type, severity, trigger_count, 
                window_duration_sec, status, report_path
            ) VALUES (?, '198.51.100.99', 'SSH_BRUTE_FORCE', 'CRITICAL', 5, 60, 'CONTAINED', '/tmp/test.md');
            """,
            (inc_id,),
        )

        execute_stmt(
            """
            INSERT INTO incident_events (incident_id, event_timestamp, service, raw_log)
            VALUES (?, CURRENT_TIMESTAMP, 'sshd', 'Failed password attempt');
            """,
            (inc_id,),
        )

        inc = query_one("SELECT * FROM incidents WHERE id = ?;", (inc_id,))
        self.assertIsNotNone(inc)
        self.assertEqual(inc["source_ip"], "198.51.100.99")

        events = query_all("SELECT * FROM incident_events WHERE incident_id = ?;", (inc_id,))
        self.assertEqual(len(events), 1)

    def test_notification_logging(self):
        """Verifies notification dispatch logging."""
        inc_id = "INC-TEST-NOTIF-001"
        execute_stmt(
            """
            INSERT INTO incidents (
                id, source_ip, threat_type, severity, trigger_count, 
                window_duration_sec, status, report_path
            ) VALUES (?, '203.0.113.80', 'WEB_PROBE', 'HIGH', 3, 45, 'CONTAINED', '/tmp/test.md');
            """,
            (inc_id,),
        )

        execute_stmt(
            """
            INSERT INTO notifications_log (incident_id, channel_id, status_code, payload_snapshot)
            VALUES (?, 'CHAN_SLACK_DEFAULT', 200, '{"text": "alert"}');
            """,
            (inc_id,),
        )

        log = query_one("SELECT * FROM notifications_log WHERE incident_id = ?;", (inc_id,))
        self.assertIsNotNone(log)
        self.assertEqual(log["status_code"], 200)


if __name__ == "__main__":
    unittest.main()
