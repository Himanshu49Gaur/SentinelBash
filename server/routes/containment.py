"""
SentinelBash - Containment & SOAR Management Endpoints
Provides manual IP quarantine, unban, rule flush, and active ban inspections.
"""

import os
import subprocess
from datetime import datetime, timezone
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status

from auth.dependencies import get_current_user, require_analyst, require_admin
from db.database import query_all, query_one, execute_stmt
from models.schemas import ActiveBanResponse, ManualBlockRequest, ManualUnbanRequest
from utils.audit import log_audit

router = APIRouter(prefix="/api/v1/containment", tags=["SOAR & Netfilter Containment"])

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def run_bash_containment(args: List[str]) -> subprocess.CompletedProcess:
    """Executes containment.sh via bash with cross-platform fallback."""
    containment_script = os.path.join(PROJECT_ROOT, "bin", "containment.sh")
    cmd = ["bash", containment_script] + args
    if os.name == "nt":
        git_bash = r"C:\Program Files\Git\bin\bash.exe"
        if os.path.exists(git_bash):
            cmd = [git_bash, containment_script] + args

    return subprocess.run(
        cmd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


@router.get("/bans", response_model=List[ActiveBanResponse])
async def list_active_bans(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Returns currently active packet-filter containment drop rules."""
    rows = query_all(
        """
        SELECT f.id, f.incident_id, f.target_ip AS ip_address, f.chain, f.action, 
               f.rule_comment_tag, f.is_active, f.applied_at, f.expires_at
        FROM firewall_rules f
        WHERE f.is_active = 1
        ORDER BY f.applied_at DESC;
        """
    )
    return [ActiveBanResponse(**r) for r in rows]


@router.post("/block", response_model=ActiveBanResponse)
async def manual_block_ip(
    req: ManualBlockRequest,
    current_user: Dict[str, Any] = Depends(require_analyst),
):
    """Manually isolates an IP address via Netfilter and opens an incident dossier."""
    ip = req.ip.strip()
    inc_id = f"INC-MANUAL-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{os.urandom(2).hex()}"

    # Execute containment.sh
    res = run_bash_containment(["block", ip, inc_id, req.vector, req.reason, str(req.duration_seconds)])
    if res.returncode == 2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target IP '{ip}' is in whitelist! Containment prohibited.",
        )
    elif res.returncode != 0:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Containment execution failed: {res.stderr or res.stdout}",
        )

    # Insert incident record
    execute_stmt(
        """
        INSERT INTO incidents (
            id, source_ip, threat_type, severity, trigger_count, 
            window_duration_sec, status, firewall_rule, ban_duration_sec, report_path
        ) VALUES (?, ?, ?, 'HIGH', 1, 0, 'CONTAINED', ?, ?, ?)
        ON CONFLICT(id) DO NOTHING;
        """,
        (inc_id, ip, req.vector, f"iptables -I INPUT -s {ip} -j DROP", req.duration_seconds, f"data/incidents/{inc_id}.md"),
    )

    log_audit(
        action="MANUAL_CONTAIN",
        target_entity="FIREWALL_RULE",
        target_id=inc_id,
        change_summary=f"Operator '{current_user['username']}' manually blocked IP '{ip}' (Reason: {req.reason})",
        actor_user_id=current_user["id"],
        actor_role=current_user["role"],
    )

    return ActiveBanResponse(
        incident_id=inc_id,
        ip_address=ip,
        chain="INPUT",
        action="DROP",
        rule_comment_tag=f"SENTINEL:{inc_id}",
        is_active=True,
        applied_at=datetime.now(timezone.utc).isoformat(),
        driver="mock",
    )


@router.post("/unban")
async def manual_unban_ip(
    req: ManualUnbanRequest,
    current_user: Dict[str, Any] = Depends(require_analyst),
):
    """Lifts firewall quarantine from an IP address and resolves active incidents."""
    ip = req.ip.strip()
    res = run_bash_containment(["unban", ip])
    if res.returncode != 0:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unban execution failed: {res.stderr or res.stdout}",
        )

    # Mark active incidents as manually released
    execute_stmt(
        """
        UPDATE incidents
        SET status = 'MANUALLY_RELEASED',
            released_by_user_id = ?,
            released_at = CURRENT_TIMESTAMP,
            release_reason = ?
        WHERE source_ip = ? AND status = 'CONTAINED';
        """,
        (current_user["id"], req.reason, ip),
    )

    # Mark firewall rule inactive
    execute_stmt(
        """
        UPDATE firewall_rules
        SET is_active = 0,
            removed_at = CURRENT_TIMESTAMP,
            removal_actor = ?
        WHERE target_ip = ? AND is_active = 1;
        """,
        (current_user["username"], ip),
    )

    log_audit(
        action="MANUAL_UNBAN",
        target_entity="FIREWALL_RULE",
        target_id=ip,
        change_summary=f"Operator '{current_user['username']}' unbanned IP '{ip}' (Reason: {req.reason})",
        actor_user_id=current_user["id"],
        actor_role=current_user["role"],
    )

    return {"status": "SUCCESS", "message": f"Containment lifted for {ip}"}


@router.post("/flush")
async def emergency_flush_all(current_user: Dict[str, Any] = Depends(require_admin)):
    """Emergency administrator purge of all active Netfilter quarantine rules."""
    res = run_bash_containment(["flush"])
    if res.returncode != 0:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Flush execution failed: {res.stderr or res.stdout}",
        )

    execute_stmt(
        """
        UPDATE firewall_rules
        SET is_active = 0,
            removed_at = CURRENT_TIMESTAMP,
            removal_actor = 'EMERGENCY_FLUSH'
        WHERE is_active = 1;
        """
    )

    execute_stmt(
        """
        UPDATE incidents
        SET status = 'MANUALLY_RELEASED',
            released_at = CURRENT_TIMESTAMP,
            release_reason = 'Emergency Administrator Flush'
        WHERE status = 'CONTAINED';
        """
    )

    log_audit(
        action="EMERGENCY_FLUSH",
        target_entity="FIREWALL_RULE",
        target_id="ALL",
        change_summary=f"Admin '{current_user['username']}' flushed ALL active containment drop rules",
        actor_user_id=current_user["id"],
        actor_role=current_user["role"],
    )

    return {"status": "SUCCESS", "message": "All Sentinel netfilter rules flushed successfully"}
