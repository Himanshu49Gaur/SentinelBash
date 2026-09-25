"""
SentinelBash - REST API & Authentication Test Suite
Tests authentication, JWT rotation, RBAC, incidents, containment, rules, and telemetry.
"""

import os
import sys
import unittest
from fastapi.testclient import TestClient

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
SERVER_DIR = os.path.join(PROJECT_ROOT, "server")

if SERVER_DIR not in sys.path:
    sys.path.insert(0, SERVER_DIR)

from main import app
from db.init_db import init_database, hash_password
from db.database import execute_stmt

client = TestClient(app)


class TestSentinelAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_database()
        # Create an Analyst test user
        analyst_id = "usr_TEST_ANALYST_01"
        analyst_pass = hash_password("AnalystPass2026!")
        execute_stmt(
            """
            INSERT INTO users (id, username, email, password_hash, role, is_active)
            VALUES (?, 'test_analyst', 'analyst@sentinel.secops', ?, 'ANALYST', 1)
            ON CONFLICT(username) DO NOTHING;
            """,
            (analyst_id, analyst_pass),
        )

        # Create an Auditor test user
        auditor_id = "usr_TEST_AUDITOR_01"
        auditor_pass = hash_password("AuditorPass2026!")
        execute_stmt(
            """
            INSERT INTO users (id, username, email, password_hash, role, is_active)
            VALUES (?, 'test_auditor', 'auditor@sentinel.secops', ?, 'AUDITOR', 1)
            ON CONFLICT(username) DO NOTHING;
            """,
            (auditor_id, auditor_pass),
        )

    def test_01_health_and_metrics(self):
        """Verifies health check and telemetry metrics endpoints."""
        r = client.get("/api/v1/health")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("status", data)
        self.assertIn("daemons", data)
        self.assertIn("database", data)

        r_metrics = client.get("/api/v1/metrics")
        self.assertEqual(r_metrics.status_code, 200)
        metrics = r_metrics.json()
        self.assertIn("total_incidents", metrics)
        self.assertIn("threat_breakdown", metrics)

    def test_02_admin_login_and_token_refresh(self):
        """Verifies JWT issuance and refresh token rotation."""
        # 1. Login with bad credentials
        r_fail = client.post("/api/v1/auth/token", json={"username": "admin", "password": "WrongPassword"})
        self.assertEqual(r_fail.status_code, 401)

        # 2. Login with valid credentials
        r = client.post("/api/v1/auth/token", json={"username": "admin", "password": "AdminSentinel2026!"})
        self.assertEqual(r.status_code, 200)
        token_data = r.json()
        self.assertIn("access_token", token_data)
        self.assertIn("refresh_token", token_data)
        self.assertEqual(token_data["user"]["role"], "ADMIN")

        access_token = token_data["access_token"]
        refresh_token = token_data["refresh_token"]

        # 3. Test /me profile endpoint
        r_me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access_token}"})
        self.assertEqual(r_me.status_code, 200)
        self.assertEqual(r_me.json()["username"], "admin")

        # 4. Test refresh token exchange
        r_ref = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
        self.assertEqual(r_ref.status_code, 200)
        new_token_data = r_ref.json()
        self.assertIn("access_token", new_token_data)
        self.assertNotEqual(new_token_data["access_token"], access_token)

    def test_03_api_key_authentication(self):
        """Verifies API key authentication for automated tools."""
        valid_key = "snt_live_bootstrap_master_admin_key_2026"
        r = client.get("/api/v1/incidents", headers={"X-API-Key": valid_key})
        self.assertEqual(r.status_code, 200)

        # Bad key
        r_bad = client.get("/api/v1/incidents", headers={"X-API-Key": "snt_live_invalid_key"})
        self.assertEqual(r_bad.status_code, 401)

    def test_04_rules_and_whitelist(self):
        """Verifies rules retrieval and whitelist management."""
        admin_key = "snt_live_bootstrap_master_admin_key_2026"
        headers = {"X-API-Key": admin_key}

        # 1. Get detection rules
        r_rules = client.get("/api/v1/rules", headers=headers)
        self.assertEqual(r_rules.status_code, 200)
        rules = r_rules.json()
        self.assertGreaterEqual(len(rules), 3)

        # 2. Update detection rule
        r_up = client.put(
            "/api/v1/rules/RULE_SSH_BRUTE_FORCE",
            headers=headers,
            json={"threshold_count": 6, "window_seconds": 65},
        )
        self.assertEqual(r_up.status_code, 200)
        self.assertEqual(r_up.json()["threshold_count"], 6)

        # 3. Whitelist listing and addition
        test_ip = "192.0.2.100"
        r_add_wl = client.post(
            "/api/v1/whitelist",
            headers=headers,
            json={"cidr_or_ip": test_ip, "label": "Test SecOps Jump Box"},
        )
        self.assertEqual(r_add_wl.status_code, 200)
        wl_entry = r_add_wl.json()
        self.assertEqual(wl_entry["cidr_or_ip"], test_ip)

        # 4. Whitelist deletion
        r_del = client.delete(f"/api/v1/whitelist/{wl_entry['id']}", headers=headers)
        self.assertEqual(r_del.status_code, 200)

    def test_05_containment_and_immunity(self):
        """Verifies manual quarantine and whitelist immunity blocking."""
        admin_key = "snt_live_bootstrap_master_admin_key_2026"
        headers = {"X-API-Key": admin_key}

        # 1. Try blocking whitelisted IP (127.0.0.1) -> should fail with 400
        r_immune = client.post(
            "/api/v1/containment/block",
            headers=headers,
            json={"ip": "127.0.0.1", "reason": "Test attack", "vector": "MANUAL", "duration_seconds": 3600},
        )
        self.assertEqual(r_immune.status_code, 400)
        self.assertIn("whitelist", r_immune.json()["detail"].lower())

        # 2. Block malicious attacker IP
        attacker_ip = "203.0.113.199"
        r_block = client.post(
            "/api/v1/containment/block",
            headers=headers,
            json={"ip": attacker_ip, "reason": "REST API Unit Test", "vector": "MANUAL", "duration_seconds": 3600},
        )
        self.assertEqual(r_block.status_code, 200)
        self.assertEqual(r_block.json()["ip_address"], attacker_ip)

        # 3. Check active bans
        r_bans = client.get("/api/v1/containment/bans", headers=headers)
        self.assertEqual(r_bans.status_code, 200)
        banned_ips = [b["ip_address"] for b in r_bans.json()]
        self.assertIn(attacker_ip, banned_ips)

        # 4. Unban attacker IP
        r_unban = client.post(
            "/api/v1/containment/unban",
            headers=headers,
            json={"ip": attacker_ip, "reason": "Test cleanup"},
        )
        self.assertEqual(r_unban.status_code, 200)

    def test_06_rbac_enforcement(self):
        """Verifies Role-Based Access Control restrictions."""
        # 1. Login as AUDITOR
        r_aud = client.post("/api/v1/auth/token", json={"username": "test_auditor", "password": "AuditorPass2026!"})
        aud_token = r_aud.json()["access_token"]
        aud_headers = {"Authorization": f"Bearer {aud_token}"}

        # Auditor CAN view incidents
        r_view = client.get("/api/v1/incidents", headers=aud_headers)
        self.assertEqual(r_view.status_code, 200)

        # Auditor CANNOT trigger manual containment (Requires ANALYST or ADMIN)
        r_block = client.post(
            "/api/v1/containment/block",
            headers=aud_headers,
            json={"ip": "198.51.100.40", "reason": "Auditor containment", "vector": "MANUAL", "duration_seconds": 3600},
        )
        self.assertEqual(r_block.status_code, 403)

        # Auditor CANNOT flush rules (Requires ADMIN)
        r_flush = client.post("/api/v1/containment/flush", headers=aud_headers)
        self.assertEqual(r_flush.status_code, 403)

        # Auditor CANNOT modify rules (Requires ADMIN)
        r_rule_mod = client.put(
            "/api/v1/rules/RULE_SSH_BRUTE_FORCE",
            headers=aud_headers,
            json={"threshold_count": 99},
        )
        self.assertEqual(r_rule_mod.status_code, 403)


if __name__ == "__main__":
    unittest.main()
