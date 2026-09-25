"""
SentinelBash - Detection Rules & Whitelist Management Endpoints
Provides tuning for threat detection thresholds and management of immune CIDR subnets.
"""

import os
import hashlib
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status

from auth.dependencies import get_current_user, require_admin, require_analyst
from db.database import query_all, query_one, execute_stmt
from models.schemas import (
    DetectionRuleResponse,
    DetectionRuleUpdate,
    WhitelistEntryResponse,
    WhitelistCreate,
)
from utils.audit import log_audit

router = APIRouter(prefix="/api/v1", tags=["Detection Rules & Whitelist"])

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WHITELIST_CONF_PATH = os.path.join(PROJECT_ROOT, "config", "whitelist.conf")


@router.get("/rules", response_model=List[DetectionRuleResponse])
async def list_detection_rules(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Retrieves all active heuristic threat detection rules and parameters."""
    rows = query_all("SELECT * FROM detection_rules ORDER BY created_at ASC;")
    return [DetectionRuleResponse(**r) for r in rows]


@router.put("/rules/{rule_id}", response_model=DetectionRuleResponse)
async def update_detection_rule(
    rule_id: str,
    update_data: DetectionRuleUpdate,
    current_user: Dict[str, Any] = Depends(require_admin),
):
    """Updates threshold limits, sliding window sizes, or enabled status for a rule."""
    existing = query_one("SELECT * FROM detection_rules WHERE id = ?;", (rule_id,))
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_id}' not found",
        )

    # Build dynamic update statement
    fields = []
    values = []
    update_dict = update_data.model_dump(exclude_unset=True)

    for k, v in update_dict.items():
        fields.append(f"{k} = ?")
        values.append(v)

    if not fields:
        return DetectionRuleResponse(**existing)

    fields.append("updated_at = CURRENT_TIMESTAMP")
    values.append(rule_id)

    set_clause = ", ".join(fields)
    execute_stmt(f"UPDATE detection_rules SET {set_clause} WHERE id = ?;", tuple(values))

    log_audit(
        action="RULE_UPDATE",
        target_entity="DETECTION_RULE",
        target_id=rule_id,
        change_summary=f"Admin '{current_user['username']}' modified rule '{rule_id}' parameters",
        actor_user_id=current_user["id"],
        actor_role=current_user["role"],
        state_delta={"before": dict(existing), "after": update_dict},
    )

    updated = query_one("SELECT * FROM detection_rules WHERE id = ?;", (rule_id,))
    return DetectionRuleResponse(**updated)


@router.get("/whitelist", response_model=List[WhitelistEntryResponse])
async def list_whitelist(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Retrieves all immune IP addresses and CIDR subnets exempt from quarantine."""
    rows = query_all("SELECT * FROM whitelist_entries WHERE is_active = 1 ORDER BY created_at ASC;")
    return [WhitelistEntryResponse(**r) for r in rows]


@router.post("/whitelist", response_model=WhitelistEntryResponse)
async def add_whitelist_entry(
    entry: WhitelistCreate,
    current_user: Dict[str, Any] = Depends(require_analyst),
):
    """Registers a new immune IP/CIDR in both SQLite and config/whitelist.conf."""
    cidr = entry.cidr_or_ip.strip()
    wl_id = f"WL-{hashlib.md5(cidr.encode()).hexdigest()[:8].upper()}"

    execute_stmt(
        """
        INSERT INTO whitelist_entries (id, cidr_or_ip, label, added_by_user_id, is_active, notes)
        VALUES (?, ?, ?, ?, 1, ?)
        ON CONFLICT(cidr_or_ip) DO UPDATE SET
            label = excluded.label,
            is_active = 1,
            notes = excluded.notes;
        """,
        (wl_id, cidr, entry.label, current_user["id"], entry.notes),
    )

    # Append to config/whitelist.conf if not already present
    if os.path.exists(WHITELIST_CONF_PATH):
        try:
            with open(WHITELIST_CONF_PATH, "r", encoding="utf-8") as f:
                content = f.read()
            if cidr not in content:
                with open(WHITELIST_CONF_PATH, "a", encoding="utf-8") as f:
                    f.write(f"\n{cidr} # {entry.label}\n")
        except Exception as e:
            print(f"[!] Warning: Failed to sync whitelist.conf: {e}")

    log_audit(
        action="WHITELIST_ADD",
        target_entity="WHITELIST",
        target_id=wl_id,
        change_summary=f"Operator '{current_user['username']}' added whitelist subnet '{cidr}'",
        actor_user_id=current_user["id"],
        actor_role=current_user["role"],
    )

    created = query_one("SELECT * FROM whitelist_entries WHERE id = ?;", (wl_id,))
    return WhitelistEntryResponse(**created)


@router.delete("/whitelist/{entry_id}")
async def remove_whitelist_entry(
    entry_id: str,
    current_user: Dict[str, Any] = Depends(require_admin),
):
    """Deactivates a whitelist immunity entry."""
    entry = query_one("SELECT * FROM whitelist_entries WHERE id = ?;", (entry_id,))
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Whitelist entry '{entry_id}' not found",
        )

    execute_stmt("UPDATE whitelist_entries SET is_active = 0 WHERE id = ?;", (entry_id,))

    log_audit(
        action="WHITELIST_REMOVE",
        target_entity="WHITELIST",
        target_id=entry_id,
        change_summary=f"Admin '{current_user['username']}' removed whitelist entry '{entry['cidr_or_ip']}'",
        actor_user_id=current_user["id"],
        actor_role=current_user["role"],
    )

    return {"status": "SUCCESS", "message": f"Whitelist entry '{entry['cidr_or_ip']}' deactivated"}
