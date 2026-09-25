"""
SentinelBash - Authentication & Cryptographic Security Tier
Handles password hashing, JWT encoding/decoding, token rotation, and API key verification.
"""

import os
import hmac
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
import jwt

# JWT Secrets and Timing Configurations
JWT_SECRET_KEY = os.environ.get("SENTINEL_JWT_SECRET", "sentinel_soc_super_secret_jwt_key_2026_change_in_production")
JWT_ALGORITHM = "HS256"
JWT_ISSUER = "sentinel-bash-auth"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("SENTINEL_ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.environ.get("SENTINEL_REFRESH_TOKEN_EXPIRE_DAYS", "7"))


def hash_password(password: str, salt: Optional[str] = None) -> str:
    """Computes a cryptographically salted SHA-256 hash."""
    if not salt:
        salt = secrets.token_hex(16)
    salted = f"{salt}:{password}".encode("utf-8")
    digest = hashlib.sha256(salted).hexdigest()
    return f"sha256${salt}${digest}"


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """Verifies a plaintext password against the stored salted hash."""
    if not stored_hash or not plain_password:
        return False

    parts = stored_hash.split("$")
    if len(parts) == 3 and parts[0] == "sha256":
        salt = parts[1]
        expected_digest = parts[2]
        computed = hashlib.sha256(f"{salt}:{plain_password}".encode("utf-8")).hexdigest()
        return hmac.compare_digest(computed, expected_digest)

    # Legacy or fallback un-salted comparison
    computed = hashlib.sha256(plain_password.encode("utf-8")).hexdigest()
    return hmac.compare_digest(computed, stored_hash)


def hash_api_key(api_key: str) -> str:
    """Computes SHA-256 hash of API key for indexed database lookup."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Encodes a signed JWT access token with standard claims and unique jti."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({
        "exp": expire,
        "iat": now,
        "iss": JWT_ISSUER,
        "jti": secrets.token_hex(16),
    })
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decodes and validates a JWT token; raises jwt.PyJWTError on failure."""
    return jwt.decode(
        token,
        JWT_SECRET_KEY,
        algorithms=[JWT_ALGORITHM],
        issuer=JWT_ISSUER,
        options={"require": ["exp", "sub", "role"]}
    )


def generate_refresh_token() -> str:
    """Generates a secure 256-bit random hex refresh token."""
    return secrets.token_hex(32)


def hash_token(token: str) -> str:
    """Computes SHA-256 hash of session/refresh token for database storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
