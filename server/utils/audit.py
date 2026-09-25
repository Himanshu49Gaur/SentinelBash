"""
SentinelBash - Security Audit Logging Utility
Maintains immutable compliance ledger of administrative and automated actions.
"""

import json
from typing import Optional, Dict, Any
from db.database import execute_stmt


def log_audit(
    action: str,
    target_entity: str,
    target_id: Optional[str] = None,
    change_summary: str = "",
    actor_user_id: Optional[str] = None,
    actor_role: str = "SYSTEM",
    ip_address: Optional[str] = None,
    state_delta: Optional[Dict[str, Any]] = None,
) -> None:
    """Records an administrative event into the audit_logs table."""
    delta_json = json.dumps(state_delta) if state_delta else None
    try:
        execute_stmt(
            """
            INSERT INTO audit_logs (
                actor_user_id, actor_role, action, target_entity, 
                target_id, ip_address, change_summary, state_delta_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                actor_user_id,
                actor_role,
                action,
                target_entity,
                target_id,
                ip_address,
                change_summary,
                delta_json,
            ),
        )
    except Exception as e:
        # Prevent audit logging failure from failing the main operation
        print(f"[!] Warning: Audit log failed: {e}")
