"""
SentinelBash - FastAPI Authentication & RBAC Dependencies
Enforces JWT and API key security policies across protected REST routes.
"""

from typing import Optional, Dict, Any, List
from fastapi import Depends, HTTPException, status, Header, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt

from auth.security import decode_access_token, hash_api_key
from db.database import query_one

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    auth_header: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> Dict[str, Any]:
    """Authenticates the caller via either JWT Bearer token or X-API-Key header."""
    # 1. Check API Key Authentication
    if x_api_key:
        key_hash = hash_api_key(x_api_key)
        user = query_one(
            "SELECT id, username, email, role, is_active, created_at FROM users WHERE api_key_hash = ? AND is_active = 1;",
            (key_hash,),
        )
        if user:
            return user
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # 2. Check JWT Bearer Token Authentication
    if auth_header and auth_header.credentials:
        token = auth_header.credentials
        try:
            payload = decode_access_token(token)
            user_id = payload.get("sub")
            if not user_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token payload",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            user = query_one(
                "SELECT id, username, email, role, is_active, created_at FROM users WHERE id = ? AND is_active = 1;",
                (user_id,),
            )
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User account inactive or not found",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return user
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Access token has expired",
                headers={"WWW-Authenticate": "Bearer error=\"invalid_token\", error_description=\"The token has expired\""},
            )
        except jwt.PyJWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide Bearer token or X-API-Key.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_roles(allowed_roles: List[str]):
    """Returns a dependency that verifies the authenticated user possesses one of the allowed roles."""
    def role_checker(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        user_role = current_user.get("role", "")
        if user_role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires one of the following roles: {', '.join(allowed_roles)}. Your role: {user_role}",
            )
        return current_user
    return role_checker


# Role shortcut dependencies
require_admin = require_roles(["ADMIN"])
require_analyst = require_roles(["ADMIN", "ANALYST"])
require_auditor = require_roles(["ADMIN", "ANALYST", "AUDITOR"])
