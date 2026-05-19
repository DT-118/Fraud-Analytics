import json
import uuid
import random
import time
from datetime import datetime, timezone

import requests

FRAUD_SCORE_API = "http://localhost:8080/v1/score"


def send_request(payload: dict, label: str):
    try:
        response = requests.post(FRAUD_SCORE_API, json=payload)
        print(f"{label} → {response.status_code}")
    except Exception as e:
        print("Request failed:", e)


def base_payload(action: str, subject_id: str):
    return {
        "correlation_id": str(uuid.uuid4()),
        "transaction_id": str(uuid.uuid4()),
        "event_id": str(uuid.uuid4()),
        "subject_id": subject_id,
        "session_id": str(uuid.uuid4()),
        "request_id": str(uuid.uuid4()),
        "actor_type": "citizen",
        "actor_id": None,
        "action_taxonomy": action,
        "event_time": datetime.now(timezone.utc).isoformat(),
        "environment": "prod",
        "security_payload": {
            "src_ip": f"10.0.0.{random.randint(1,255)}",
            "device_id": f"device-{random.randint(1,5)}",
            "geo_loc": random.choice(["IN", "US", "DE"]),
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
        "wallet_payload": None,
        "success": random.choice([True, False]),
    }


def send_login():
    payload = base_payload("login", f"user-{random.randint(1,10)}")
    send_request(payload, "LOGIN")


def send_enroll():
    payload = base_payload("enroll", f"user-{random.randint(1,10)}")
    payload["document_payload"] = {
        "doc_type": "PASSPORT",
        "document_scan_passed": random.choice([True, False]),
        "doc_face_matched": random.choice([True, False]),
    }
    send_request(payload, "ENROLL")


def send_consent():
    payload = base_payload("consent", f"user-{random.randint(1,10)}")
    payload["consent_payload"] = {
        "consent_id": str(uuid.uuid4()),
        "operation": random.choice(["grant", "use"]),
        "scope": "email",
        "allowed_scopes": ["email"],
    }
    send_request(payload, "CONSENT")


def send_wallet():
    payload = base_payload("wallet", f"user-{random.randint(1,10)}")
    payload["wallet_payload"] = {
        "wallet_id": f"wallet-{random.randint(1,3)}",
        "wallet_action": random.choice(["sign", "export_key"]),
        "is_critical": random.choice([True, False]),
    }
    send_request(payload, "WALLET")


actions = [send_login, send_enroll, send_consent, send_wallet]

print("Starting fraud simulator...")

while True:
    random.choice(actions)()
    time.sleep(0.5)   # adjust speed here
