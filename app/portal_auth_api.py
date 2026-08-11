"""
auth_api.py

POST /auth/register  — create a new user
POST /auth/login     — verify credentials, return JWT + role + session info
"""

from dotenv import load_dotenv

load_dotenv()
import os
import re
from datetime import datetime, timezone, timedelta
from typing import Literal

import bcrypt
import jwt
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator

from zoneinfo import ZoneInfo

_IST = ZoneInfo("Asia/Kolkata")

from core.logger import logger
from storage.db import get_db_connection, release_db_connection
from storage.portal_auth_repo import (
    create_user,
    get_user_by_username,
    username_exists,
    mobile_exists,
)

router = APIRouter(prefix="/auth", tags=["Auth"])

_JWT_SECRET      = os.environ.get("JWT_SECRET","")       # required — fail loud at startup
_JWT_ALGORITHM   = "HS256"
_JWT_EXPIRY_HOURS = int(os.environ.get("JWT_EXPIRY_HOURS", "8"))
_MOBILE_RE       = re.compile(r"^\+?[0-9]{7,15}$")


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    name:     str
    mobile:   str
    username: str
    password: str

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("name cannot be empty")
        return v

    @field_validator("username")
    @classmethod
    def username_valid(cls, v):
        v = v.strip()
        if len(v) < 3 or len(v) > 50:
            raise ValueError("username must be 3–50 characters")
        if not re.match(r"^[a-zA-Z0-9_]+$", v):
            raise ValueError("username can only contain letters, numbers, underscores")
        return v

    @field_validator("password")
    @classmethod
    def password_strong(cls, v):
        if len(v) < 8:
            raise ValueError("password must be at least 8 characters")
        return v

    @field_validator("mobile")
    @classmethod
    def mobile_valid(cls, v):
        v = v.strip()
        if not _MOBILE_RE.match(v):
            raise ValueError("invalid mobile number")
        return v

    class Config:
        extra = "forbid"


class LoginRequest(BaseModel):
    username: str
    password: str

    class Config:
        extra = "forbid"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=12)).decode()


def _verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def _generate_token(user_id: str, username: str, role: str) -> tuple[str, datetime, datetime]:
    expires_at_utc = datetime.now(timezone.utc) + timedelta(hours=_JWT_EXPIRY_HOURS)
    expires_at_ist = expires_at_utc.astimezone(_IST)

    payload = {
        "sub":      user_id,
        "username": username,
        "role":     role,
        "exp":      expires_at_utc,    # JWT always stores UTC internally
        "iat":      datetime.now(timezone.utc),
    }
    token = jwt.encode(payload, _JWT_SECRET, algorithm=_JWT_ALGORITHM)
    return token, expires_at_utc, expires_at_ist


# ---------------------------------------------------------------------------
# POST /auth/register
# ---------------------------------------------------------------------------

@router.post("/register", status_code=201)
def register(body: RegisterRequest):
    """
    Register a new user.

    Checks:
      - username not already taken
      - mobile not already taken
    Hashes password with bcrypt (cost 12) before storing.
    """
    db = get_db_connection()
    try:
        if username_exists(db, body.username):
            raise HTTPException(status_code=409, detail="Username already taken")

        if mobile_exists(db, body.mobile):
            raise HTTPException(status_code=409, detail="Mobile number already registered")

        hashed = _hash_password(body.password)

        user = create_user(
            db,
            name=body.name,
            mobile=body.mobile,
            username=body.username,
            hashed_password=hashed,
            role="SERVICE_PROVIDER",
        )

        logger.info("[AUTH] Registered user=%s role=%s", body.username, "SERVICE_PROVIDER")

        return {
            "message": "User registered successfully",
            "user": {
                "id":       user["id"],
                "name":     user["name"],
                "username": user["username"],
                "role":     user["role"],
            },
        }

    except HTTPException:
        raise
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("[AUTH] Register failed username=%s", body.username)
        raise HTTPException(status_code=500, detail="Registration failed") from exc
    finally:
        release_db_connection(db)


# ---------------------------------------------------------------------------
# POST /auth/login
# ---------------------------------------------------------------------------

@router.post("/login")
def login(body: LoginRequest):
    """
    Authenticate a user and return a JWT.

    Response includes:
      token      — Bearer JWT
      role       — ADMIN | SERVICE_PROVIDER  (frontend uses this for routing)
      expiresAt  — ISO timestamp the token expires
      sessionDuration — hours the session lasts
    """
    db = get_db_connection()
    try:
        user = get_user_by_username(db, body.username)

        # Same error message for both "not found" and "wrong password"
        # — never reveal which one failed
        if not user:
            raise HTTPException(status_code=401, detail="Invalid username or password")

        if not user["is_active"]:
            raise HTTPException(status_code=403, detail="Account is deactivated")

        if not _verify_password(body.password, user["password"]):
            logger.warning("[AUTH] Failed login attempt username=%s", body.username)
            raise HTTPException(status_code=401, detail="Invalid username or password")

        token, expires_at_utc, expires_at_ist = _generate_token(
                user_id=user["id"],
                username=user["username"],
                role=user["role"],
            )

        now_ist = datetime.now(_IST)

        logger.info("[AUTH] Login success username=%s role=%s", body.username, user["role"])

        return {
            "token":           token,
            "tokenType":       "Bearer",
            "expiresAt":       expires_at_ist.strftime("%Y-%m-%d %I:%M %p IST"),
            "sessionDuration": f"{_JWT_EXPIRY_HOURS} hours (expires at {expires_at_ist.strftime('%I:%M %p IST')})",
            "user": {
                "id":       user["id"],
                "name":     user["name"],
                "username": user["username"],
                "role":     user["role"],
            },
        }

    except HTTPException:
        raise
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("[AUTH] Login failed username=%s", body.username)
        raise HTTPException(status_code=500, detail="Login failed") from exc
    finally:
        release_db_connection(db)