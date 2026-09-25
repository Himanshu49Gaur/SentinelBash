"""
SentinelBash - Authentication & Session Endpoints
Provides operator login, token issuance, refresh token rotation, and profile queries.
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request

from auth.security import (
    verify_password,
    create_access_token,
    generate_refresh_token,
    hash_token,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_DAYS,
)
from auth.dependencies import get_current_user
from db.database import query_one, execute_stmt
from models.schemas import TokenRequest, TokenResponse, RefreshTokenRequest, UserResponse
from utils.audit import log_audit

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication & Session"])


@router.post("/token", response_model=TokenResponse)
async def login_for_access_token(credentials: TokenRequest, request: Request):
    """Authenticates operator credentials and returns signed JWT access & refresh tokens."""
    user = query_one(
        "SELECT id, username, email, password_hash, role, is_active, created_at FROM users WHERE username = ?;",
        (credentials.username,),
    )

    if not user or not user["is_active"] or not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Issue JWT access token
    access_token = create_access_token(
        data={"sub": user["id"], "username": user["username"], "role": user["role"]}
    )

    # Issue and store refresh token
    refresh_token = generate_refresh_token()
    token_digest = hash_token(refresh_token)
    session_id = f"ses_{token_digest[:16]}"
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Unknown")
    expires_at = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    execute_stmt(
        """
        INSERT INTO sessions (id, user_id, token_hash, ip_address, user_agent, expires_at)
        VALUES (?, ?, ?, ?, ?, ?);
        """,
        (session_id, user["id"], token_digest, client_ip, user_agent, expires_at.isoformat()),
    )

    # Update last_login timestamp
    execute_stmt("UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?;", (user["id"],))

    log_audit(
        action="USER_LOGIN",
        target_entity="USER",
        target_id=user["id"],
        change_summary=f"Operator '{user['username']}' authenticated successfully",
        actor_user_id=user["id"],
        actor_role=user["role"],
        ip_address=client_ip,
    )

    user_resp = UserResponse(
        id=user["id"],
        username=user["username"],
        email=user["email"],
        role=user["role"],
        is_active=bool(user["is_active"]),
        created_at=user["created_at"],
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        refresh_token=refresh_token,
        user=user_resp,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_access_token(req: RefreshTokenRequest, request: Request):
    """Exchanges an unrevoked refresh token for a fresh access token with token rotation."""
    token_digest = hash_token(req.refresh_token)
    session = query_one(
        """
        SELECT s.id, s.user_id, s.expires_at, s.revoked_at, u.username, u.email, u.role, u.is_active, u.created_at
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token_hash = ?;
        """,
        (token_digest,),
    )

    if not session or session["revoked_at"] is not None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked refresh token",
        )

    # Check expiration
    expires_dt = datetime.fromisoformat(session["expires_at"].replace("Z", "+00:00"))
    if datetime.now(timezone.utc) > expires_dt:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired. Please re-authenticate.",
        )

    # Revoke old session and issue rotated refresh token
    new_refresh = generate_refresh_token()
    new_digest = hash_token(new_refresh)
    new_session_id = f"ses_{new_digest[:16]}"
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Unknown")
    new_expires = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    execute_stmt("UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP WHERE id = ?;", (session["id"],))
    execute_stmt(
        """
        INSERT INTO sessions (id, user_id, token_hash, ip_address, user_agent, expires_at)
        VALUES (?, ?, ?, ?, ?, ?);
        """,
        (new_session_id, session["user_id"], new_digest, client_ip, user_agent, new_expires.isoformat()),
    )

    access_token = create_access_token(
        data={"sub": session["user_id"], "username": session["username"], "role": session["role"]}
    )

    user_resp = UserResponse(
        id=session["user_id"],
        username=session["username"],
        email=session["email"],
        role=session["role"],
        is_active=bool(session["is_active"]),
        created_at=session["created_at"],
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        refresh_token=new_refresh,
        user=user_resp,
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Returns the authenticated operator profile."""
    return UserResponse(
        id=current_user["id"],
        username=current_user["username"],
        email=current_user["email"],
        role=current_user["role"],
        is_active=bool(current_user["is_active"]),
        created_at=current_user["created_at"],
    )
