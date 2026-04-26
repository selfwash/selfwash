"""JWT auth, password hashing, and permission keys for dashboard users."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Set

import jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.orm import Session

from db import AppUser, AppUserPermission

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

JWT_SECRET = os.environ.get("JWT_SECRET", "").strip()
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.environ.get("JWT_EXPIRE_MINUTES", "10080"))  # 7 days

# --- Permission keys (store in app_user_permissions.permission) ---
PERM_NAYAX_READ = "nayax.read"
PERM_MACHINES_READ = "machines.read"
PERM_MACHINES_WRITE = "machines.write"
PERM_ADMIN_USERS = "admin.users"

ALL_KNOWN_PERMISSIONS: frozenset[str] = frozenset(
    {
        PERM_NAYAX_READ,
        PERM_MACHINES_READ,
        PERM_MACHINES_WRITE,
        PERM_ADMIN_USERS,
    }
)

# app_users.review_status (signup workflow)
REVIEW_PENDING = "pending"
REVIEW_APPROVED = "approved"
REVIEW_REJECTED = "rejected"


@dataclass
class AuthContext:
    """api_key: legacy full access. jwt: per-user permissions."""

    source: str
    user: Optional[AppUser] = None
    permissions: Set[str] = field(default_factory=set)

    def has(self, perm: str) -> bool:
        if self.source == "api_key":
            return True
        if self.user and self.user.is_superuser:
            return True
        return perm in self.permissions


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, password_hash: str) -> bool:
    return pwd_context.verify(plain, password_hash)


def create_access_token(*, user_id: int) -> str:
    if not JWT_SECRET:
        raise RuntimeError("JWT_SECRET is not set")
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload: dict[str, Any] = {"sub": str(user_id), "iat": now, "exp": exp}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    if not JWT_SECRET:
        raise ValueError("JWT_SECRET not set")
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


def load_permissions_for_user(db: Session, user: AppUser) -> Set[str]:
    if user.is_superuser:
        return set(ALL_KNOWN_PERMISSIONS)
    rows = db.scalars(select(AppUserPermission.permission).where(AppUserPermission.user_id == user.id)).all()
    return {str(p) for p in rows if p}
