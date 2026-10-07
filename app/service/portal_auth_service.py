"""
services/portal_auth_service.py

Business logic for portal authentication. Single home for:

  1. Email OTP         stateless generation, signed challenge and verification
  2. Password reset    forgot / reset password flow

Rules:
  - OTPs are never stored or logged. The challenge token sent to the client
    contains only an HMAC of (email + nonce + otp), keyed with a server secret,
    so the OTP cannot be derived from it. Nothing OTP-related is written to the
    database. Redis holds only short-lived counters (resend cooldown, attempt
    count, single-use marker).
  - Raw reset tokens are never stored or logged. Only their SHA-256 hash is
    persisted.
  - The reset service functions take an open DB connection and never commit or
    roll back; the caller (API layer) owns the transaction.

Env:
  OTP_HMAC_SECRET      (required)
  FRONTEND_URL         (required)
  OTP_LENGTH           (default 8)
  OTP_TTL_SECONDS      (default 300)
  OTP_MAX_ATTEMPTS     (default 5)
  RESET_TOKEN_MINUTES  (default 15)
  RESET_MAX_PER_HOUR   (default 3)
"""

import hashlib
import jwt
import hmac
import os
import secrets
import time
from typing import Callable, NamedTuple, Optional
from storage.redis_client import redis_client
from core.logger import logger
from core.email_sender import (
    send_password_reset_email,
    send_password_changed_email,
)
from storage.portal_auth_repo import (
    find_user_for_reset,
    count_recent_tokens,
    invalidate_active_tokens,
    create_reset_token,
    consume_reset_token,
    update_user_password,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_OTP_HMAC_SECRET = os.environ.get("OTP_HMAC_SECRET", "")
if not _OTP_HMAC_SECRET:
    raise RuntimeError("OTP_HMAC_SECRET environment variable is required")

FRONTEND_URL = os.environ.get("FRONTEND_URL", "").rstrip("/")
if not FRONTEND_URL:
    raise RuntimeError("FRONTEND_URL environment variable is required")

RESET_TOKEN_MINUTES = int(os.environ.get("RESET_TOKEN_MINUTES", "15"))
RESET_MAX_PER_HOUR = int(os.environ.get("RESET_MAX_PER_HOUR", "3"))
OTP_LENGTH       = int(os.environ.get("OTP_LENGTH", "8"))
OTP_TTL_SECONDS  = int(os.environ.get("OTP_TTL_SECONDS", "300"))
OTP_MAX_ATTEMPTS = int(os.environ.get("OTP_MAX_ATTEMPTS", "5"))

# Different key from login JWT and registration token, so tokens can't cross-pass
_OTP_CHALLENGE_SECRET = _OTP_HMAC_SECRET + ":otp-challenge"

# ===========================================================================
# Email OTP
# ===========================================================================

def generate_otp() -> str:
    """Cryptographically secure numeric code, zero-padded to OTP_LENGTH digits."""
    return f"{secrets.randbelow(10 ** OTP_LENGTH):0{OTP_LENGTH}d}"


def _otp_mac(email: str, nonce: str, otp: str) -> str:
    return hmac.new(
        _OTP_HMAC_SECRET.encode(),
        f"{email}:{nonce}:{otp}".encode(),
        hashlib.sha256,
    ).hexdigest()


def build_otp_challenge(email: str, otp: str) -> str:
    """Signed token the client sends back with the OTP. The OTP itself is not inside it."""
    now = int(time.time())
    nonce = secrets.token_urlsafe(16)
    payload = {
        "sub":   email,
        "typ":   "otp_challenge",
        "nonce": nonce,
        "h":     _otp_mac(email, nonce, otp),
        "iat":   now,
        "exp":   now + OTP_TTL_SECONDS,
    }
    return jwt.encode(payload, _OTP_CHALLENGE_SECRET, algorithm="HS256")


def verify_otp_challenge(email: str, otp: str, challenge_token: str) -> bool:
    """
    True only if: token is valid and unexpired, belongs to this email, the OTP
    matches, attempts are not exhausted, and the challenge was not used before.
    Redis errors propagate (fail closed).
    """
    try:
        payload = jwt.decode(challenge_token, _OTP_CHALLENGE_SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError:          # includes expired
        return False

    if payload.get("typ") != "otp_challenge" or payload.get("sub") != email:
        return False

    nonce = payload.get("nonce")
    expected = payload.get("h")
    if not nonce or not expected:
        return False

    remaining = max(1, int(payload["exp"] - time.time()))

    # Attempt limit per challenge
    try_key = f"otp:try:{nonce}"
    attempts = redis_client.incr(try_key)
    if attempts == 1:
        redis_client.expire(try_key, remaining + 5)
    if attempts > OTP_MAX_ATTEMPTS:
        return False

    if not hmac.compare_digest(expected, _otp_mac(email, nonce, otp)):
        return False

    # Single use: first successful verify claims the nonce
    claimed = redis_client.set(f"otp:used:{nonce}", "1", nx=True, ex=remaining + 5)
    return bool(claimed)


def claim_send_cooldown(email: str, cooldown_seconds: int) -> int:
    """Returns 0 if the send is allowed, else seconds to wait. Fails open on Redis errors."""
    key = f"otp:cooldown:{email}"
    try:
        if redis_client.set(key, "1", nx=True, ex=cooldown_seconds):
            return 0
        return max(1, int(redis_client.ttl(key)))
    except Exception as exc:
        logger.warning("[AUTH] OTP cooldown check failed, allowing send: %s", exc)
        return 0


def release_send_cooldown(email: str) -> None:
    try:
        redis_client.delete(f"otp:cooldown:{email}")
    except Exception:
        pass


# ===========================================================================
# Password reset
# ===========================================================================


class ResetLink(NamedTuple):
    email: str
    name: str
    raw_token: str


class PasswordChanged(NamedTuple):
    email: str
    name: str


def hash_reset_token(raw: str) -> str:
    """SHA 256 hex of the raw reset token."""
    return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Step 1: forgot password
# ---------------------------------------------------------------------------


def issue_reset_token(db, identifier: str) -> Optional[ResetLink]:
    """
    Resolve an email/username and create a fresh single-use token.

    Returns a ResetLink to email, or None when nothing should be sent
    (unknown user, inactive account, or rate limit hit). The caller must
    return the same response in every case and commit when a link is returned.
    """
    user = find_user_for_reset(db, identifier)

    if not user or not user["is_active"]:
        return None

    if count_recent_tokens(db, user["id"]) >= RESET_MAX_PER_HOUR:
        logger.warning("[RESET] Rate limit hit user_id=%s", user["id"])
        return None

    raw_token = secrets.token_urlsafe(32)  # ~256 bits of entropy

    invalidate_active_tokens(db, user["id"])  # only the newest link works
    create_reset_token(db, user["id"], hash_reset_token(raw_token), RESET_TOKEN_MINUTES)

    logger.info("[RESET] Token issued user_id=%s", user["id"])
    return ResetLink(email=user["email"], name=user["name"], raw_token=raw_token)


# ---------------------------------------------------------------------------
# Step 2: reset password
# ---------------------------------------------------------------------------


def complete_reset(
    db,
    raw_token: str,
    new_password: str,
    hash_password: Callable[[str], str],
) -> Optional[PasswordChanged]:
    """
    Atomically consume the token and set the new password.

    Returns PasswordChanged on success, or None if the token is invalid,
    expired, already used, or the account is no longer active. The caller
    must roll back on None and commit on success.
    """
    user_id = consume_reset_token(db, hash_reset_token(raw_token))
    if not user_id:
        return None

    updated = update_user_password(db, user_id, hash_password(new_password))
    if not updated:
        return None

    invalidate_active_tokens(db, user_id)  # kill any other outstanding links

    name, email = updated
    logger.info("[RESET] Password reset user_id=%s", user_id)
    return PasswordChanged(email=email, name=name)


# ---------------------------------------------------------------------------
# Emails (used as FastAPI background tasks; must never raise)
# ---------------------------------------------------------------------------


def send_reset_link_email(link: ResetLink) -> None:
    try:
        url = f"{FRONTEND_URL}/reset-password?token={link.raw_token}"
        send_password_reset_email(link.email, link.name, url, RESET_TOKEN_MINUTES)
    except Exception:
        # Deliberately not logging the URL or token
        logger.exception("[RESET] Failed to send reset email")


def send_password_changed_notice(changed: PasswordChanged) -> None:
    try:
        send_password_changed_email(changed.email, changed.name)
    except Exception:
        logger.exception("[RESET] Failed to send password-changed email")