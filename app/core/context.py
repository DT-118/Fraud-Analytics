"""
Canonical fraud-event context and payload validation.

Context is the validated event boundary shared by API ingestion, Kafka
consumers, feature extraction, rule evaluation, and persistence.

Configuration:
    Validation limits are read from environment variables at process startup.
    The application entry point is responsible for loading .env files; this
    module must not call load_dotenv() as an import-time side effect.
"""

from __future__ import annotations
import ipaddress
import os
import re
from datetime import datetime, timedelta, timezone
from pydantic import BaseModel, ConfigDict, field_validator, model_validator
from core.constants import (
    ACTOR_TYPE_TO_ROLE, VALID_ACTOR_TYPES, VALID_ENVIRONMENTS,
    VALID_ROLES, VALID_SUB_METHODS, VALID_TAXONOMIES,
)
from core.ids import normalize_event_id


# ---------------------------------------------------------------------------
# Validation limits
# ---------------------------------------------------------------------------
# These protect the API/Kafka boundary from malformed or unexpectedly large
# identifiers. They are environment-configurable because deployments may have
# different database/schema constraints.
def _get_positive_int_env(name: str, default: int) -> int:
    """
    Read a positive integer from the environment.

    Raises:
        RuntimeError: If the configured value is not a positive integer.
    """
    raw_value = os.getenv(name, str(default))

    try:
        value = int(raw_value)
    except ValueError as exc:
        raise RuntimeError(
            f"{name} must be a positive integer; got {raw_value!r}"
        ) from exc

    if value <= 0:
        raise RuntimeError(
            f"{name} must be greater than zero; got {value}"
        )

    return value

_MAX_FUTURE_SECONDS = _get_positive_int_env(
    "MAX_FUTURE_SECONDS_TOLERANCE",
    300,
)

_MAX_AGE_SECONDS = _get_positive_int_env(
    "MAX_EVENT_AGE_SECONDS",
    3600,
)

_SUBJECT_ID_MAX_LEN = _get_positive_int_env(
    "SUBJECT_ID_MAX_LEN",
    128,
)

_SESSION_ID_MAX_LEN = _get_positive_int_env(
    "SESSION_ID_MAX_LEN",
    128,
)

_EMIRATES_ID_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


class SecurityPayload(BaseModel):
    """Security and device attributes used by fraud features."""

    model_config = ConfigDict(extra="ignore")

    src_ip: str
    device_id: str 
    geo_loc: str | None = None
    timezone: str | None = None
    user_agent: str | None = None
    browser_name: str | None = None
    browser_version: str | None = None
    os_version: str | None = None
    screen_resolution: str | None = None
    language: str | None = None

    @field_validator("src_ip")
    @classmethod
    def validate_src_ip(cls, value: str) -> str:
        """Require a syntactically valid IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(
                f"src_ip must be a valid IP address, got: {value!r}"
            ) from exc
        return value


class BiometricPayload(BaseModel):
    """Optional biometric verification and liveness attributes."""

    model_config = ConfigDict(extra="ignore")

    modality: str | None = None  # FACE | FINGER | IRIS
    match_score: float | None = None  # 0.0–1.0
    liveness_result: str | None = None  # LIVE | SPOOF
    liveness_required: bool = False
    face_udb_matched : bool | None = None

    @field_validator("match_score")
    @classmethod
    def validate_match_score(cls, value: float | None) -> float | None:
        """Require biometric match scores to remain within 0.0–1.0."""
        if value is not None and not 0.0 <= value <= 1.0:
            raise ValueError("match_score must be between 0.0 and 1.0")
        return value


class DocumentPayload(BaseModel):
    """Optional document verification attributes used during login."""

    model_config = ConfigDict(extra="ignore")

    doc_type: str | None = None  # PASSPORT | ID | DL
    document_udb_matched: bool = False


class ConsentPayload(BaseModel):
    """Consent operation details."""

    model_config = ConfigDict(extra="ignore")

    consent_id: str
    operation: str  # grant | use | revoke


class WalletPayload(BaseModel):
    """Wallet operation details."""

    model_config = ConfigDict(extra="ignore")

    wallet_id: str
    credential_id: str
    wallet_action: str  # provision | share


class Context(BaseModel):
    """
    Canonical fraud event.

    Extra fields are ignored intentionally so producers can evolve without
    breaking this consumer contract. Required engine/persistence fields are
    explicitly validated at the event boundary.
    """

    model_config = ConfigDict(extra="ignore")

    # -----------------------------------------------------------------------
    # Identifiers
    # -----------------------------------------------------------------------
    correlation_id: str
    transaction_id: str
    event_id: str
    subject_id: str
    session_id: str 
    request_id: str | None = None

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------
    emirates_id_hash: str | None = None
    role: str | None = None
    exception_code: str | None = None

    # -----------------------------------------------------------------------
    # Actor
    # -----------------------------------------------------------------------
    actor_type: str
    actor_id: str | None = None

    # -----------------------------------------------------------------------
    # Action
    # -----------------------------------------------------------------------
    action_taxonomy: str
    action_taxonomy_sub_method: str | None = None   # e.g. pin, wallet (auth only)
    event_time: datetime
    environment: str
    # Caller asserts biometric authentication was used for this event.
    # Not taxonomy-restricted — AUTH, WALLET, and CONSENT can all send it.
    biometric_method: bool = False

    # -----------------------------------------------------------------------
    # Payloads
    # -----------------------------------------------------------------------
    security_payload: SecurityPayload
    biometric_payload: BiometricPayload | None = None
    document_payload: DocumentPayload | None = None
    consent_payload: ConsentPayload | None = None
    wallet_payload: WalletPayload | None = None

    # -----------------------------------------------------------------------
    # Event result
    # -----------------------------------------------------------------------
    success: bool

    @field_validator("event_id")
    @classmethod
    def validate_event_id(cls, value: str) -> str:
        """
        Require canonical UUID form and normalize to lowercase so the Redis
        idempotency key, Postgres row and API response all agree.
        """
        return normalize_event_id(value)

    @field_validator("session_id")
    @classmethod
    def validate_session_id(cls, value: str | None) -> str | None:
        """Keep session_id within the configured database-backed limit."""
        if value is not None and len(value) > _SESSION_ID_MAX_LEN:
            raise ValueError(
                f"session_id must not exceed {_SESSION_ID_MAX_LEN} characters"
            )
        return value

    @field_validator("subject_id")
    @classmethod
    def validate_subject_id(cls, value: str) -> str:
        """Reject empty, oversized, and control-character subject IDs."""
        if not value or not value.strip():
            raise ValueError("subject_id must not be empty")
        if len(value) > _SUBJECT_ID_MAX_LEN:
            raise ValueError(
                f"subject_id must not exceed {_SUBJECT_ID_MAX_LEN} characters"
            )
        if any(character in value for character in ("\n", "\r", "\x00")):
            raise ValueError("subject_id must not contain control characters")
        return value

    @field_validator("role")
    @classmethod
    def validate_role(cls, value: str | None) -> str | None:
        """Require roles to use the canonical role vocabulary (case-insensitive)."""
        if value is None:
            return None
        value = value.strip().upper()
        if value not in VALID_ROLES:
            raise ValueError(f"role must be one of {sorted(VALID_ROLES)}")
        return value

    @field_validator("actor_type")
    @classmethod
    def validate_actor_type(cls, value: str) -> str:
        """Require the canonical actor-type vocabulary (case-insensitive)."""
        value = value.strip().lower()
        if value not in VALID_ACTOR_TYPES:
            raise ValueError(
                f"actor_type must be one of {sorted(VALID_ACTOR_TYPES)}"
            )
        return value

    @field_validator("action_taxonomy")
    @classmethod
    def validate_taxonomy(cls, value: str) -> str:
        """Require the canonical incoming service taxonomy."""
        if value not in VALID_TAXONOMIES:
            raise ValueError(
                f"action_taxonomy must be one of {sorted(VALID_TAXONOMIES)}"
            )
        return value

    @field_validator("action_taxonomy_sub_method")
    @classmethod
    def normalize_sub_method(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip().lower()
        return value or None

    @model_validator(mode="after")
    def validate_sub_method(self):
        method = self.action_taxonomy_sub_method
        if method is None:
            return self
        allowed = VALID_SUB_METHODS.get(self.action_taxonomy)
        if allowed is None:
            raise ValueError(
                f"action_taxonomy_sub_method is not supported for "
                f"action_taxonomy {self.action_taxonomy!r}"
            )
        if method not in allowed:
            raise ValueError(
                f"action_taxonomy_sub_method must be one of {sorted(allowed)}, got {method!r}"
            )
        return self

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, value: str) -> str:
        """Require a supported execution environment."""
        if value not in VALID_ENVIRONMENTS:
            raise ValueError(
                f"environment must be one of {sorted(VALID_ENVIRONMENTS)}"
            )
        return value

    @field_validator("event_time")
    @classmethod
    def validate_event_time(cls, value: datetime) -> datetime:
        """
        Reject events outside the accepted time window.

        event_time must carry an explicit UTC offset. Naive timestamps are
        rejected rather than silently assumed to be UTC, since a caller sending
        local time without an offset would otherwise be misinterpreted.
        """
        if value.tzinfo is None:
            raise ValueError(
                "event_time must include an explicit UTC offset "
                "(e.g. '+00:00', '+05:30', or 'Z') — naive timestamps are "
                "rejected, not assumed to be UTC"
            )

        now = datetime.now(timezone.utc)
        value_utc = value.astimezone(timezone.utc)

        if value_utc > now + timedelta(seconds=_MAX_FUTURE_SECONDS):
            raise ValueError(
                f"event_time cannot be more than {_MAX_FUTURE_SECONDS} seconds in the future"
            )
        if value_utc < now - timedelta(seconds=_MAX_AGE_SECONDS):
            raise ValueError(
                f"event_time cannot be more than {_MAX_AGE_SECONDS} seconds in the past"
            )

        return value_utc

    @field_validator("emirates_id_hash")
    @classmethod
    def validate_emirates_id_hash(
        cls,
        value: str | None,
    ) -> str | None:
        """Require a lowercase SHA-256 hexadecimal digest when supplied."""
        if value is not None and not _EMIRATES_ID_HASH_RE.fullmatch(value):
            raise ValueError(
                "emirates_id_hash must be a lowercase 64-character "
                "hexadecimal SHA-256 digest"
            )
        return value

    @property
    def effective_role(self) -> str | None:
        """
        Role used for role modifiers, whichever field the caller filled in.

        - only one of role / actor_type gives a role  -> that one
        - both agree                                  -> that one
        - they disagree                               -> the more specific one.
          CITIZEN is the "no dampening" default, so if one side says CITIZEN
          and the other says something else (e.g. VISITOR), the non-CITIZEN
          value wins. If both are non-CITIZEN and differ, `role` wins.
        """
        from_role = self.role
        from_actor = ACTOR_TYPE_TO_ROLE.get(self.actor_type)

        if from_role and from_actor and from_role != from_actor:
            return from_actor if from_role == "CITIZEN" else from_role
        return from_role or from_actor