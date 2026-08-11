"""
Unified fraud event context.

This module defines the canonical event contract used across the fraud engine:
- API ingestion
- Kafka consumers
- Feature extraction
- Rule evaluation
- Persistence

The Context object is immutable and validated at the boundary. All fields are
validated strictly; unknown extra fields are silently ignored so the API can
evolve without breaking existing callers.
"""

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from pydantic import BaseModel, field_validator

VALID_ROLES       = {"CITIZEN", "RESIDENT", "VISITOR", "AGENT", "ADMIN", "SYSTEM"}
VALID_TAXONOMIES  = {"login", "enroll", "consent", "wallet"}
VALID_ENVIRONMENTS = {"prod", "staging", "sandbox"}
VALID_ACTOR_TYPES = {"citizen", "admin", "service"}

_EMIRATES_ID_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_FUTURE_SECONDS  = 300    # 5 minutes of clock skew tolerated
_MAX_AGE_SECONDS     = 3600   # reject replays older than 1 hour
_SUBJECT_ID_MAX_LEN  = 128


class SecurityPayload(BaseModel):
    src_ip: str
    device_id: Optional[str] = None
    geo_loc: Optional[str] = None
    timezone: Optional[str] = None
    user_agent: Optional[str] = None
    browser_name: Optional[str] = None
    os_version: Optional[str] = None
    screen_resolution: Optional[str] = None
    language: Optional[str] = None

    @field_validator("src_ip")
    @classmethod
    def validate_src_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"src_ip must be a valid IP address, got: {v!r}") from exc
        return v

    class Config:
        extra = "ignore"


class BiometricPayload(BaseModel):
    modality: Optional[str] = None        # FACE | FINGER | IRIS
    match_score: Optional[float] = None   # 0.0 – 1.0
    liveness_result: Optional[str] = None # LIVE | SPOOF
    liveness_required: bool = False

    @field_validator("match_score")
    @classmethod
    def validate_match_score(cls, v):
        if v is not None and not (0.0 <= v <= 1.0):
            raise ValueError("match_score must be between 0.0 and 1.0")
        return v

    class Config:
        extra = "ignore"


class DocumentPayload(BaseModel):
    doc_type: Optional[str] = None        # PASSPORT | ID | DL
    document_scan_passed: bool = False
    doc_face_matched: Optional[bool] = None

    class Config:
        extra = "ignore"


class ConsentPayload(BaseModel):
    consent_id: str
    operation: str                        # grant | use | revoke

    class Config:
        extra = "ignore"


class WalletPayload(BaseModel):
    wallet_id: str
    wallet_action: str                    # provision | share

    class Config:
        extra = "ignore"


class Context(BaseModel):
    # ---------------- IDENTIFIERS ----------------
    correlation_id: str
    transaction_id: str
    event_id: str
    subject_id: str                       # SUID — primary identity key
    session_id: Optional[str] = None
    request_id: Optional[str] = None

    # ---------------- IDENTITY EXTENSION ----------------
    emirates_id_hash: Optional[str] = None  # SHA-256 of Emirates ID — never store raw
    role: Optional[str] = None              # CITIZEN | AGENT | ADMIN | SYSTEM
    exception_code: Optional[str] = None   # caller-reported anomaly code

    # ---------------- ACTOR ----------------
    actor_type: str                       # citizen / admin / service
    actor_id: Optional[str] = None

    # ---------------- ACTION ----------------
    action_taxonomy: str                  # login | enroll | consent | wallet
    event_time: datetime
    environment: str                      # prod | staging | sandbox

    # authentication_type: legacy field — accepted but not used in scoring
    authentication_type: Optional[str] = None

    # ---------------- PAYLOADS ----------------
    security_payload: SecurityPayload
    biometric_payload: Optional[BiometricPayload] = None
    document_payload: Optional[DocumentPayload] = None
    consent_payload: Optional[ConsentPayload] = None
    wallet_payload: Optional[WalletPayload] = None

    # ---------------- RESULT ----------------
    success: bool

    @field_validator("subject_id")
    @classmethod
    def validate_subject_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("subject_id must not be empty")
        if len(v) > _SUBJECT_ID_MAX_LEN:
            raise ValueError(f"subject_id must not exceed {_SUBJECT_ID_MAX_LEN} characters")
        if "\n" in v or "\r" in v or "\x00" in v:
            raise ValueError("subject_id must not contain control characters")
        return v

    @field_validator("role")
    @classmethod
    def validate_role(cls, v):
        if v is not None and v not in VALID_ROLES:
            raise ValueError(f"role must be one of {VALID_ROLES}")
        return v

    @field_validator("action_taxonomy")
    @classmethod
    def validate_taxonomy(cls, v):
        if v not in VALID_TAXONOMIES:
            raise ValueError(f"action_taxonomy must be one of {VALID_TAXONOMIES}")
        return v

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v):
        if v not in VALID_ENVIRONMENTS:
            raise ValueError(f"environment must be one of {VALID_ENVIRONMENTS}")
        return v

    @field_validator("actor_type")
    @classmethod
    def validate_actor_type(cls, v):
        if v not in VALID_ACTOR_TYPES:
            raise ValueError(f"actor_type must be one of {VALID_ACTOR_TYPES}")
        return v

    @field_validator("event_time")
    @classmethod
    def validate_event_time(cls, v):
        now = datetime.now(timezone.utc)
        v_utc = v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        if v_utc > now + timedelta(seconds=_MAX_FUTURE_SECONDS):
            raise ValueError(
                f"event_time cannot be more than {_MAX_FUTURE_SECONDS}s in the future"
            )
        if v_utc < now - timedelta(seconds=_MAX_AGE_SECONDS):
            raise ValueError(
                f"event_time cannot be more than {_MAX_AGE_SECONDS}s in the past "
                f"(possible replay attack)"
            )
        return v

    @field_validator("emirates_id_hash")
    @classmethod
    def validate_emirates_id_hash(cls, v):
        if v is not None and not _EMIRATES_ID_HASH_RE.match(v):
            raise ValueError(
                "emirates_id_hash must be a lowercase 64-character hex string (SHA-256)"
            )
        return v

    class Config:
        extra = "ignore"
