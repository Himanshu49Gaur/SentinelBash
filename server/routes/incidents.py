"""
SentinelBash - Incident Management & Forensic Review Endpoints
Provides search, filtering, detailed dossier rendering, and manual release workflows.
"""

import os
import subprocess
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status

from auth.dependencies import get_current_user, require_analyst
from db.database import query_all, query_one, execute_stmt
from models.schemas import (
    IncidentResponse,
    IncidentDetailResponse,
    IncidentEventResponse,
    IncidentReleaseRequest,
)
from utils.audit import log_audit

router = APIRouter(prefix="/api/v1/incidents", tags=["Incident Management"])

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


@router.get("", response_model=List[IncidentResponse])
async def list_incidents(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    search: Optional[str] = Query(None, description="Search by source IP or Incident ID"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Retrieves paginated, filterable incident history with threat attribution."""
    query = "SELECT * FROM incidents WHERE 1=1"
    params = []

    if status_filter and status_filter.upper() != "ALL":
        query += " AND status = ?"
        params.append(status_filter.upper())

    if severity:
        query += " AND severity = ?"
        params.append(severity.upper())

    if search:
        query += " AND (source_ip LIKE ? OR id LIKE ?)"
        like_term = f"%{search.strip()}%"
        params.extend([like_term, like_term])

    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?;"
    params.extend([limit, offset])

    rows = query_all(query, tuple(params))
    return [IncidentResponse(**r) for r in rows]


@router.get("/{incident_id}", response_model=IncidentDetailResponse)
async def get_incident_detail(
    incident_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Returns granular forensic details, raw telemetry events, and Markdown report preview."""
    inc = query_one("SELECT * FROM incidents WHERE id = ?;", (incident_id,))
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    # Fetch associated raw log events
    events = query_all(
        "SELECT * FROM incident_events WHERE incident_id = ? ORDER BY event_timestamp ASC;",
        (incident_id,),
    )

    # Read markdown report if present
    md_content = None
    report_path = inc["report_path"]
    if report_path and os.path.exists(report_path):
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                md_content = f.read()
        except Exception:
            md_content = "Failed to load report from disk."

    return IncidentDetailResponse(
        incident=IncidentResponse(**inc),
        events=[IncidentEventResponse(**e) for e in events],
        markdown_report=md_content,
    )


@router.post("/{incident_id}/release", response_model=IncidentResponse)
async def release_incident_quarantine(
    incident_id: str,
    payload: IncidentReleaseRequest,
    current_user: Dict[str, Any] = Depends(require_analyst),
):
    """Manually revokes active netfilter isolation rule and resolves incident."""
    inc = query_one("SELECT * FROM incidents WHERE id = ?;", (incident_id,))
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    attacker_ip = inc["source_ip"]

    # 1. Execute unban via containment.sh script
    containment_script = os.path.join(PROJECT_ROOT, "bin", "containment.sh")
    if os.path.exists(containment_script):
        # Execute in bash
        bash_cmd = ["bash", containment_script, "unban", attacker_ip]
        if os.name == "nt":
            git_bash = r"C:\Program Files\Git\bin\bash.exe"
            if os.path.exists(git_bash):
                bash_cmd = [git_bash, containment_script, "unban", attacker_ip]

        try:
            subprocess.run(bash_cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except Exception as e:
            print(f"[!] Warning: containment.sh unban execution error: {e}")

    # 2. Update Incident Record
    execute_stmt(
        """
        UPDATE incidents
        SET status = 'MANUALLY_RELEASED',
            released_by_user_id = ?,
            released_at = CURRENT_TIMESTAMP,
            release_reason = ?
        WHERE id = ?;
        """,
        (current_user["id"], payload.reason, incident_id),
    )

    # 3. Deactivate Firewall Rules
    execute_stmt(
        """
        UPDATE firewall_rules
        SET is_active = 0,
            removed_at = CURRENT_TIMESTAMP,
            removal_actor = ?
        WHERE target_ip = ? AND is_active = 1;
        """,
        (current_user["username"], attacker_ip),
    )

    # 4. Audit Log
    log_audit(
        action="MANUAL_UNBAN",
        target_entity="INCIDENT",
        target_id=incident_id,
        change_summary=f"Analyst '{current_user['username']}' released IP '{attacker_ip}' (Reason: {payload.reason})",
        actor_user_id=current_user["id"],
        actor_role=current_user["role"],
    )

    updated_inc = query_one("SELECT * FROM incidents WHERE id = ?;", (incident_id,))
    return IncidentResponse(**updated_inc)
