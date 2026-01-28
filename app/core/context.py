from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel

"""
Unified fraud event context.

This module defines the canonical event contract used across the fraud engine:
- API ingestion
- Kafka consumers
- Feature extraction
- Rule evaluation
- Persistence

The Context object is immutable and validated.
"""


class SecurityPayload(BaseModel):
    src_ip: str  # source IP address of request
    device_id: Optional[str]  # device fingerprint / ID
    geo_loc: Optional[str]  # country / region code (IN, US, etc.)
    timezone: Optional[str]  # client timezone
    user_agent: Optional[str]  # raw user-agent string
    client_id: Optional[str]  # app / web / partner identifier
    token_id: Optional[str]  # session / auth token id
    browser_name: Optional[str]  # parsed browser name
    os_version: Optional[str]  # OS version
    screen_resolution: Optional[str]  # screen resolution (e.g. 1920x1080)
    language: Optional[str]  # UI / browser language


class BiometricPayload(BaseModel):
    modality: Optional[str]  # FACE / FINGER / IRIS
    match_score: Optional[float]  # biometric match score (if any)
    liveness_result: Optional[str]  # LIVE / SPOOF / None
    liveness_required: bool  # policy requirement flag


class DocumentPayload(BaseModel):
    doc_type: Optional[str]  # PASSPORT / ID / DL
    document_scan_passed: bool  # MRZ / document checks result
    doc_face_matched: Optional[bool]  # document photo vs selfie match


class ConsentPayload(BaseModel):
    consent_id: str  # unique consent identifier
    scope: str  # scope being granted / used
    operation: str  # grant | use | revoke
    allowed_scopes: Optional[List[str]]  # scopes allowed for use


class WalletPayload(BaseModel):
    wallet_id: str  # wallet identifier
    wallet_action: str  # sign / export_key / add_signer / rotate_key
    is_critical: bool  # high-risk action flag


class Context(BaseModel):
    # ---------------- IDENTIFIERS ----------------
    correlation_id: str  # trace across services
    transaction_id: str  # business transaction id
    event_id: str  # unique event id
    subject_id: str  # user / entity identifier
    session_id: Optional[str]  # session id
    request_id: Optional[str]  # request id (API gateway)

    # ---------------- ACTOR ----------------
    actor_type: str  # citizen / admin / service
    actor_id: Optional[str]  # admin_id / service_id

    # ---------------- ACTION ----------------
    action_taxonomy: str  # login / enroll / consent / wallet
    event_time: datetime  # event timestamp (UTC)
    environment: str  # prod / staging / sandbox

    # ---------------- PAYLOADS ----------------
    security_payload: SecurityPayload
    biometric_payload: Optional[BiometricPayload]
    document_payload: Optional[DocumentPayload]
    consent_payload: Optional[ConsentPayload]
    wallet_payload: Optional[WalletPayload]

    # ---------------- RESULT ----------------
    success: bool  # outcome of action (true / false)

    class Config:
        extra = "forbid"  # reject unknown fields
