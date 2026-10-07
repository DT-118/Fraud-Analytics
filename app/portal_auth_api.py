"""
portal_auth_api.py

POST /auth/send-otp          email an OTP (registration step 1)
POST /auth/verify-otp        verify OTP, return short-lived registration token (step 2)
POST /auth/register          create a new user; email comes from the token (step 3)
POST /auth/login             verify credentials, return JWT + role + session info
POST /auth/forgot-password   email a password reset link (email or username)
POST /auth/reset-password    set a new password using the emailed token
"""

from dotenv import load_dotenv
load_dotenv()
import os
import re
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, field_validator
from psycopg2 import errors as pg_errors
from zoneinfo import ZoneInfo
from core.logger import logger
from storage.db import get_db_connection, release_db_connection
from core.email_sender import send_otp_email
from service.portal_auth_service import (
    # OTP
    OTP_LENGTH,
    OTP_TTL_SECONDS,
    generate_otp,
    build_otp_challenge,
    verify_otp_challenge,
    claim_send_cooldown,
    release_send_cooldown,
    # Password reset
    issue_reset_token,
    complete_reset,
    send_reset_link_email,
    send_password_changed_notice,
)
from storage.portal_auth_repo import (
    create_user,
    get_user_by_username,
    username_exists,
    mobile_exists,
    email_exists,
)

_IST = ZoneInfo("Asia/Kolkata")

router = APIRouter(prefix="/auth", tags=["Auth"])

_JWT_SECRET       = os.environ.get("JWT_SECRET", "")
if not _JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable is required")
_JWT_ALGORITHM    = "HS256"
_JWT_EXPIRY_HOURS = int(os.environ.get("JWT_EXPIRY_HOURS", "8"))

# Registration token uses a different key so it can never pass as a login JWT
_REG_SECRET        = os.environ.get("REG_TOKEN_SECRET") or (_JWT_SECRET + ":email-verification")
_REG_TOKEN_MINUTES = int(os.environ.get("REG_TOKEN_MINUTES", "10"))

_OTP_RESEND_COOLDOWN_SECONDS = int(os.environ.get("OTP_RESEND_COOLDOWN_SECONDS", "30"))

# Identical response for every forgot-password outcome (anti-enumeration)
_RESET_GENERIC_RESPONSE = {
    "message": "If an account exists, a password reset link has been sent to its registered email."
}

_MOBILE_RE = re.compile(r"^\+?[0-9]{7,15}$")
_EMAIL_RE  = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

def _normalize_email(v: str) -> str:
    v = v.strip().lower()
    if len(v) > 255 or not _EMAIL_RE.match(v):
        raise ValueError("invalid email address")
    return v


class SendOtpRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def email_valid(cls, v):
        return _normalize_email(v)

    class Config:
        extra = "forbid"


class VerifyOtpRequest(BaseModel):
    email:           str
    otp:             str
    challenge_token: str

    @field_validator("email")
    @classmethod
    def email_valid(cls, v):
        return _normalize_email(v)

    @field_validator("otp")
    @classmethod
    def otp_valid(cls, v):
        v = v.strip()
        if not re.fullmatch(rf"[0-9]{{{OTP_LENGTH}}}", v):
            raise ValueError(f"OTP must be {OTP_LENGTH} digits")
        return v

    @field_validator("challenge_token")
    @classmethod
    def token_valid(cls, v):
        v = v.strip()
        if not v or len(v) > 2048:
            raise ValueError("invalid challenge token")
        return v

    class Config:
        extra = "forbid"


class RegisterRequest(BaseModel):
    name:               str
    mobile:             str
    username:           str
    password:           str
    registration_token: str

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


class ForgotPasswordRequest(BaseModel):
    identifier: str   # email or username

    @field_validator("identifier")
    @classmethod
    def identifier_valid(cls, v):
        v = v.strip()
        if not v or len(v) > 255:
            raise ValueError("invalid identifier")
        return v

    class Config:
        extra = "forbid"


class ResetPasswordRequest(BaseModel):
    token:        str
    new_password: str

    @field_validator("token")
    @classmethod
    def token_valid(cls, v):
        v = v.strip()
        if not (20 <= len(v) <= 100):
            raise ValueError("invalid token")
        return v

    @field_validator("new_password")
    @classmethod
    def password_strong(cls, v):
        if len(v) < 8:
            raise ValueError("password must be at least 8 characters")
        return v

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


_bearer = HTTPBearer(auto_error=False, description="JWT from POST /auth/login")
_PORTAL_ROLES = {"ADMIN", "SERVICE_PROVIDER"}


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=401,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_portal_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict:
    """
    Validate the login JWT (same secret/algorithm as _generate_token).
    Returns the claims: {"sub", "username", "role", "exp", "iat"}.
    """
    if creds is None or not creds.credentials.strip():
        raise _unauthorized("Missing bearer token")

    try:
        claims = jwt.decode(
            creds.credentials,
            _JWT_SECRET,
            algorithms=[_JWT_ALGORITHM],
            options={"require": ["exp", "sub"]},
        )
    except jwt.ExpiredSignatureError:
        raise _unauthorized("Token expired. Please log in again")
    except jwt.InvalidTokenError:
        raise _unauthorized("Invalid token")

    if claims.get("role") not in _PORTAL_ROLES:
        raise _unauthorized("Invalid token")

    return claims


def require_portal_admin(claims: dict = Depends(require_portal_user)) -> dict:
    """Optional: use on any dashboard route that should be ADMIN-only."""
    if claims.get("role") != "ADMIN":
        raise HTTPException(status_code=403, detail="Admin role required")
    return claims

def _generate_registration_token(email: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": email,
        "typ": "email_verified",
        "iat": now,
        "exp": now + timedelta(minutes=_REG_TOKEN_MINUTES),
    }
    return jwt.encode(payload, _REG_SECRET, algorithm=_JWT_ALGORITHM)


def _email_from_registration_token(token: str) -> str:
    try:
        payload = jwt.decode(token, _REG_SECRET, algorithms=[_JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401,
            detail="Email verification expired. Please verify your email again")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid email verification token")

    if payload.get("typ") != "email_verified" or not payload.get("sub"):
        raise HTTPException(status_code=401, detail="Invalid email verification token")
    return payload["sub"]



# ---------------------------------------------------------------------------
# POST /auth/send-otp
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# POST /auth/verify-otp
# ---------------------------------------------------------------------------

@router.post("/send-otp")
def send_otp(body: SendOtpRequest):
    """Email a random OTP and return a signed challenge token. Nothing is stored in the DB."""
    db = get_db_connection()
    try:
        if email_exists(db, body.email):
            raise HTTPException(status_code=409, detail="Email already registered")
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("[AUTH] Send OTP lookup failed email=%s", body.email)
        raise HTTPException(status_code=500, detail="Could not send OTP") from exc
    finally:
        release_db_connection(db)

    retry_after = claim_send_cooldown(body.email, _OTP_RESEND_COOLDOWN_SECONDS)
    if retry_after:
        raise HTTPException(
            status_code=429,
            detail=f"Please wait {retry_after} seconds before requesting another OTP",
            headers={"Retry-After": str(retry_after)},
        )

    try:
        otp = generate_otp()
        send_otp_email(body.email, otp, OTP_TTL_SECONDS)
        # Built AFTER the email is sent, so the user gets the full lifetime
        challenge = build_otp_challenge(body.email, otp)
    except Exception as exc:
        release_send_cooldown(body.email)   # email never went out, so don't punish the user
        logger.exception("[AUTH] Send OTP failed email=%s", body.email)
        raise HTTPException(status_code=500, detail="Could not send OTP") from exc

    logger.info("[AUTH] OTP sent email=%s", body.email)
    return {
        "message": "OTP sent",
        "challengeToken": challenge,
        "expiresInSeconds": OTP_TTL_SECONDS,
    }


@router.post("/verify-otp")
def verify_otp(body: VerifyOtpRequest):
    """Verify OTP + challenge token. On success returns the short-lived registration token."""
    try:
        ok = verify_otp_challenge(body.email, body.otp, body.challenge_token)
    except Exception as exc:
        logger.exception("[AUTH] Verify OTP failed email=%s", body.email)
        raise HTTPException(status_code=500, detail="Verification failed") from exc

    # Same message for wrong, expired, reused or over-attempted
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    logger.info("[AUTH] Email verified email=%s", body.email)
    return {
        "message": "Email verified",
        "registrationToken": _generate_registration_token(body.email),
        "expiresInSeconds": _REG_TOKEN_MINUTES * 60,
    }


# ---------------------------------------------------------------------------
# POST /auth/register
# ---------------------------------------------------------------------------

@router.post("/register", status_code=201)
def register(body: RegisterRequest):
    """
    Register a new user. The email is taken from the verified registration
    token, never from the request body.

    Checks:
       registration token valid and unexpired
       email / username / mobile not already taken
    Hashes password with bcrypt (cost 12) before storing.
    """
    email = _email_from_registration_token(body.registration_token)

    db = get_db_connection()
    try:
        if email_exists(db, email):
            raise HTTPException(status_code=409, detail="Email already registered")

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
            email=email,
            hashed_password=hashed,
            role="SERVICE_PROVIDER",
        )

        db.commit()

        logger.info("[AUTH] Registered user=%s role=%s", body.username, "SERVICE_PROVIDER")

        return {
            "message": "User registered successfully",
            "user": {
                "id":       user["id"],
                "name":     user["name"],
                "username": user["username"],
                "email":    user["email"],
                "role":     user["role"],
            },
        }

    except HTTPException:
        db.rollback()
        raise
    except pg_errors.UniqueViolation:
        db.rollback()
        raise HTTPException(status_code=409,
            detail="Email, username or mobile number already registered")
    except RuntimeError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except Exception as exc:
        db.rollback()
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
      token       Bearer JWT
      role        ADMIN | SERVICE_PROVIDER  (frontend uses this for routing)
      expiresAtEpoch   unix timestamp the token expires
      sessionDuration  hours the session lasts
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

        logger.info("[AUTH] Login success username=%s role=%s", body.username, user["role"])

        return {
            "token":           token,
            "tokenType":       "Bearer",
            "expiresAtEpoch":  int(expires_at_utc.timestamp()),   # unix timestamp
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


# ---------------------------------------------------------------------------
# POST /auth/forgot-password
# ---------------------------------------------------------------------------

@router.post("/forgot-password")
def forgot_password(body: ForgotPasswordRequest, background_tasks: BackgroundTasks):
    """
    Accepts an email or username and emails a single-use reset link to the
    address stored on the account. The response is identical whether or not
    the account exists, is inactive, or is rate limited.
    """
    db = get_db_connection()
    try:
        db.rollback()

        link = issue_reset_token(db, body.identifier)
        if link is None:
            return _RESET_GENERIC_RESPONSE

        db.commit()

        # Sent after commit and off the request path, so response time is the
        # same for existing and non-existing accounts.
        background_tasks.add_task(send_reset_link_email, link)
        return _RESET_GENERIC_RESPONSE

    except Exception as exc:
        db.rollback()
        logger.exception("[AUTH] Forgot password failed")
        raise HTTPException(status_code=500, detail="Could not process request") from exc
    finally:
        release_db_connection(db)


# ---------------------------------------------------------------------------
# POST /auth/reset-password
# ---------------------------------------------------------------------------

@router.post("/reset-password")
def reset_password(body: ResetPasswordRequest, background_tasks: BackgroundTasks):
    """
    Consume a reset token and set a new password. Token consumption and the
    password update happen in one transaction.
    """
    db = get_db_connection()
    try:
        db.rollback()

        changed = complete_reset(db, body.token, body.new_password, _hash_password)
        if changed is None:
            db.rollback()
            raise HTTPException(status_code=400, detail="Invalid or expired reset link")

        db.commit()

        background_tasks.add_task(send_password_changed_notice, changed)
        return {"message": "Password has been reset successfully. Please log in."}

    except HTTPException:
        db.rollback()
        raise
    except Exception as exc:
        db.rollback()
        logger.exception("[AUTH] Reset password failed")
        raise HTTPException(status_code=500, detail="Could not reset password") from exc
    finally:
        release_db_connection(db)