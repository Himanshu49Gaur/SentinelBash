"""
SentinelBash - Pydantic Request & Response Data Contracts
Strict type schemas for API payloads, responses, and validation.
"""

from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field, EmailStr


# ==============================================================================
# Authentication & User Schemas
# ==============================================================================

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: str
    is_active: bool
    last_login_at: Optional[str] = None
    created_at: str


class TokenRequest(BaseModel):
    username: str = Field(..., description="Operator or daemon username")
    password: str = Field(..., description="Cleartext password")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: str
    user: UserResponse


class RefreshTokenRequest(BaseModel):
    refresh_token: str


# ==============================================================================
# Health & Telemetry Schemas
# ==============================================================================

class SystemHealthResponse(BaseModel):
    status: str
    timestamp: str
    version: str = "1.0.0"
    daemons: Dict[str, Any]
    database: Dict[str, Any]
    netfilter: Dict[str, Any]


class MetricsResponse(BaseModel):
    total_incidents: int
    active_bans_count: int
    total_events_observed: int
    whitelisted_subnets_count: int
    mttd_seconds: float = 1.2
    mttr_seconds: float = 0.8
    threat_breakdown: Dict[str, int]


# ==============================================================================
# Incident Management Schemas
# ==============================================================================

class IncidentResponse(BaseModel):
    id: str
    source_ip: str
    threat_type: str
    severity: str
    trigger_count: int
    window_duration_sec: int
    status: str
    firewall_rule: Optional[str] = None
    ban_duration_sec: int
    expires_at: Optional[str] = None
    report_path: Optional[str] = None
    released_at: Optional[str] = None
    release_reason: Optional[str] = None
    created_at: str


class IncidentEventResponse(BaseModel):
    id: int
    incident_id: str
    event_timestamp: str
    service: str
    raw_log: str
    parsed_details: Optional[str] = None


class IncidentDetailResponse(BaseModel):
    incident: IncidentResponse
    events: List[IncidentEventResponse]
    markdown_report: Optional[str] = None


class IncidentReleaseRequest(BaseModel):
    reason: str = Field("Manual analyst unban via console", description="Operator justification")


# ==============================================================================
# Containment & SOAR Schemas
# ==============================================================================

class ActiveBanResponse(BaseModel):
    id: Optional[str] = None
    incident_id: Optional[str] = None
    ip_address: str
    chain: str = "INPUT"
    action: str = "DROP"
    rule_comment_tag: str
    is_active: bool = True
    applied_at: str
    expires_at: Optional[str] = None
    driver: str = "mock"


class ManualBlockRequest(BaseModel):
    ip: str = Field(..., description="Target IPv4 to quarantine")
    reason: str = Field("Manual operator containment", description="Quarantine reason")
    vector: str = Field("MANUAL_CONTAINMENT", description="Threat classification")
    duration_seconds: int = Field(3600, description="Duration in seconds (0 = permanent)")


class ManualUnbanRequest(BaseModel):
    ip: str = Field(..., description="IPv4 address to lift quarantine from")
    reason: str = Field("Analyst manual release", description="Reason for release")


# ==============================================================================
# Detection Rules & Whitelist Schemas
# ==============================================================================

class DetectionRuleResponse(BaseModel):
    id: str
    rule_name: str
    service_target: str
    regex_pattern: str
    threshold_count: int
    window_seconds: int
    default_ban_seconds: int
    severity: str
    is_enabled: bool
    created_at: str
    updated_at: str


class DetectionRuleUpdate(BaseModel):
    threshold_count: Optional[int] = None
    window_seconds: Optional[int] = None
    default_ban_seconds: Optional[int] = None
    severity: Optional[str] = None
    is_enabled: Optional[bool] = None


class WhitelistEntryResponse(BaseModel):
    id: str
    cidr_or_ip: str
    label: str
    is_active: bool
    notes: Optional[str] = None
    created_at: str


class WhitelistCreate(BaseModel):
    cidr_or_ip: str = Field(..., description="Single IPv4 or CIDR block")
    label: str = Field(..., description="Friendly label e.g. Corporate Jump Host")
    notes: Optional[str] = None
