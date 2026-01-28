import requests
import uuid
import json
from datetime import datetime, timezone

# -------------------------------------------------------------------
# Fraud scoring API endpoint
# -------------------------------------------------------------------
FRAUD_SCORE_API = "http://localhost:8080/v1/score"


# -------------------------------------------------------------------
# Send HTTP POST request and pretty-print response
# -------------------------------------------------------------------
def send_request(payload: dict, label: str):
    response = requests.post(FRAUD_SCORE_API, json=payload)
    print(f"{label} RESPONSE:\n{json.dumps(response.json(), indent=2)}")
    print("-" * 90)


# -------------------------------------------------------------------
# Send LOGIN / AUTH event
# -------------------------------------------------------------------
def send_login_event(
    success: bool,
    *,
    subject_id: str = "user_api",
    device_id: str = "deviceA",
    geo_location: str = "IN",
    language: str = "en",
    browser_ua: str = "Chrome/120.0.0",
    screen_resolution: str = "1920x1080",
    event_hour: int = 10,
    liveness_result: str | None = None,
    liveness_required: bool = False,
):
    payload = {
        "correlation_id": str(uuid.uuid4()),
        "transaction_id": "txn-login",
        "event_id": str(uuid.uuid4()),
        "subject_id": subject_id,
        "session_id": "sess-api",
        "request_id": "req-api",
        "actor_type": "citizen",
        "actor_id": None,
        "action_taxonomy": "login",
        "event_time": datetime(
            2026, 1, 12, event_hour, 0, tzinfo=timezone.utc
        ).isoformat(),
        "environment": "prod",
        "security_payload": {
            "src_ip": "9.9.9.9",
            "device_id": device_id,
            "geo_loc": geo_location,
            "timezone": "Asia/Kolkata",
            "user_agent": browser_ua,
            "client_id": "web",
            "token_id": None,
            "browser_name": "Chrome",
            "os_version": "Windows 11",
            "screen_resolution": screen_resolution,
            "language": language,
        },
        "biometric_payload": (
            None
            if not liveness_required
            else {
                "modality": "FACE",
                "match_score": None,
                "liveness_result": liveness_result,
                "liveness_required": liveness_required,
            }
        ),
        "document_payload": None,
        "consent_payload": None,
        "wallet_payload": None,
        "success": success,
    }

    send_request(payload, "LOGIN")


# -------------------------------------------------------------------
# Send ENROLL event
# -------------------------------------------------------------------
def send_enroll_event(
    *,
    subject_id: str,
    device_id: str,
    document_scan_passed: bool = True,
    document_face_matched: bool = True,
):
    payload = {
        "correlation_id": str(uuid.uuid4()),
        "transaction_id": "txn-enroll",
        "event_id": str(uuid.uuid4()),
        "subject_id": subject_id,
        "session_id": None,
        "request_id": None,
        "actor_type": "citizen",
        "actor_id": None,
        "action_taxonomy": "enroll",
        "event_time": datetime.now(timezone.utc).isoformat(),
        "environment": "prod",
        "security_payload": {
            "src_ip": "9.9.9.9",
            "device_id": device_id,
            "geo_loc": "IN",
            "timezone": "Asia/Kolkata",
            "user_agent": "Chrome/120",
            "client_id": "web",
            "token_id": None,
            "browser_name": "Chrome",
            "os_version": "Windows",
            "screen_resolution": "1920x1080",
            "language": "en",
        },
        "biometric_payload": None,
        "document_payload": {
            "doc_type": "PASSPORT",
            "document_scan_passed": document_scan_passed,
            "doc_face_matched": document_face_matched,
        },
        "consent_payload": None,
        "wallet_payload": None,
        "success": document_scan_passed,
    }

    send_request(payload, "ENROLL")


# -------------------------------------------------------------------
# Send CONSENT event
# -------------------------------------------------------------------
def send_consent_event(
    subject_id: str,
    operation: str,
    scope: str = "email",
):
    payload = {
        "correlation_id": str(uuid.uuid4()),
        "transaction_id": "txn-consent",
        "event_id": str(uuid.uuid4()),
        "subject_id": subject_id,
        "session_id": None,
        "request_id": None,
        "actor_type": "citizen",
        "actor_id": None,
        "action_taxonomy": "consent",
        "event_time": datetime.now(timezone.utc).isoformat(),
        "environment": "prod",
        "security_payload": {
            "src_ip": "9.9.9.9",
            "device_id": "deviceA",
            "geo_loc": "IN",
            "timezone": "Asia/Kolkata",
            "user_agent": "Chrome",
            "client_id": "web",
            "token_id": None,
            "browser_name": "Chrome",
            "os_version": "Windows",
            "screen_resolution": "1920x1080",
            "language": "en",
        },
        "biometric_payload": None,
        "document_payload": None,
        "consent_payload": {
            "consent_id": str(uuid.uuid4()),
            "operation": operation,
            "scope": scope,
            "allowed_scopes": ["email"],
        },
        "wallet_payload": None,
        "success": True,
    }

    send_request(payload, "CONSENT")


# -------------------------------------------------------------------
# Send WALLET event
# -------------------------------------------------------------------
def send_wallet_event(
    subject_id: str,
    wallet_id: str,
    action: str,
    is_critical: bool,
):
    payload = {
        "correlation_id": str(uuid.uuid4()),
        "transaction_id": "txn-wallet",
        "event_id": str(uuid.uuid4()),
        "subject_id": subject_id,
        "session_id": None,
        "request_id": None,
        "actor_type": "citizen",
        "actor_id": None,
        "action_taxonomy": "wallet",
        "event_time": datetime.now(timezone.utc).isoformat(),
        "environment": "prod",
        "security_payload": {
            "src_ip": "9.9.9.9",
            "device_id": "deviceA",
            "geo_loc": "IN",
            "timezone": "Asia/Kolkata",
            "user_agent": "Chrome",
            "client_id": "web",
            "token_id": None,
            "browser_name": "Chrome",
            "os_version": "Windows",
            "screen_resolution": "1920x1080",
            "language": "en",
        },
        "biometric_payload": None,
        "document_payload": None,
        "consent_payload": None,
        "wallet_payload": {
            "wallet_id": wallet_id,
            "wallet_action": action,
            "is_critical": is_critical,
        },
        "success": True,
    }

    send_request(payload, "WALLET")


# ================= RUN TEST SCENARIOS =================

# AUTH + LIVENESS
send_login_event(False)
send_login_event(False)
send_login_event(False)  # AUTH-01
send_login_event(True)  # AUTH-03
send_login_event(True, device_id="X")  # AUTH-04
send_login_event(True, geo_location="US")  # AUTH-05
send_login_event(False, liveness_result="SPOOF", liveness_required=True)
send_login_event(False, liveness_result="SPOOF", liveness_required=True)
send_login_event(True, liveness_required=True)

# ENROLL
send_enroll_event(subject_id="e1", device_id="D1", document_scan_passed=False)
send_enroll_event(subject_id="e1", device_id="D1", document_scan_passed=False)
send_enroll_event(subject_id="e2", device_id="D2", document_face_matched=False)
send_enroll_event(subject_id="e2", device_id="D2", document_face_matched=False)
send_enroll_event(subject_id="e3", device_id="SHARED")
send_enroll_event(subject_id="e4", device_id="SHARED")
send_enroll_event(subject_id="e5", device_id="SHARED")

# CONSENT
for _ in range(6):
    send_consent_event("user_api", "grant")

send_consent_event("user_api", "use", scope="phone")  # CONS-02

# WALLET
for _ in range(6):
    send_wallet_event("user_api", "wallet-1", "sign", False)

send_wallet_event("user_api", "wallet-1", "export_key", True)
