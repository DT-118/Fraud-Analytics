from datetime import datetime


def build_splunk_event(event_context):
    """
    Build a clean, flattened Splunk event from Context object.
    Handles all action types safely.
    """

    # ---------------- Safe payload extraction ----------------
    biometric = getattr(event_context, "biometric_payload", None)
    security = getattr(event_context, "security_payload", None)
    consent = getattr(event_context, "consent_payload", None)
    wallet = getattr(event_context, "wallet_payload", None)
    document = getattr(event_context, "document_payload", None)

    # ---------------- Safe datetime conversion ----------------
    event_time = getattr(event_context, "event_time", None)
    if isinstance(event_time, datetime):
        event_time = event_time.isoformat()

    # ---------------- Base Event ----------------
    event = {
        # Core
        "event_type": "fraud_event",
        "action_taxonomy": getattr(event_context, "action_taxonomy", None),
        "actor_type": getattr(event_context, "actor_type", None),
        "authentication_type": getattr(event_context, "authentication_type", None),
        "subject_id": getattr(event_context, "subject_id", None),
        "success": getattr(event_context, "success", None),

        # Identifiers
        "correlation_id": getattr(event_context, "correlation_id", None),
        "transaction_id": getattr(event_context, "transaction_id", None),
        "event_id": getattr(event_context, "event_id", None),
        "request_id": getattr(event_context, "request_id", None),

        # Time
        "event_time": event_time,

        # ---------------- Security (IMPORTANT FIXED BLOCK) ----------------
        "security_src_ip": getattr(security, "src_ip", None),
        "security_device_id": getattr(security, "device_id", None),
        "security_geo_loc": getattr(security, "geo_loc", None),
        "security_timezone": getattr(security, "timezone", None),
        "security_browser_name": getattr(security, "browser_name", None),
        "security_os_version": getattr(security, "os_version", None),
        "security_screen_resolution": getattr(security, "screen_resolution", None),
        "security_user_agent": getattr(security, "user_agent", None),
        "security_language": getattr(security, "language", None),
        "security_token_id": getattr(security, "token_id", None),

        # FIXED: client_id comes from security_payload
        "client_id": getattr(security, "client_id", None),

        # Session
        "session_id": getattr(event_context, "session_id", None),
        "environment": getattr(event_context, "environment", None),
    }

    # =========================================================
    # 🔥 ACTION-SPECIFIC DATA (CLEAN STRUCTURE)
    # =========================================================

    action = getattr(event_context, "action_taxonomy", None)

    # ---------------- LOGIN ----------------
    if action == "login":
        event.update({
            "biometric_modality": getattr(biometric, "modality", None),
            "biometric_match_score": getattr(biometric, "match_score", None),
            "biometric_liveness_result": getattr(biometric, "liveness_result", None),
            "biometric_liveness_required": getattr(biometric, "liveness_required", None),
        })

    # ---------------- ENROLL ----------------
    elif action == "enroll":
        event.update({
            "doc_type": getattr(document, "doc_type", None),
            "document_scan_passed": getattr(document, "document_scan_passed", None),
            "doc_face_matched": getattr(document, "doc_face_matched", None),
        })

    # ---------------- CONSENT ----------------
    elif action == "consent":
        event.update({
            "consent_id": getattr(consent, "consent_id", None),
            "consent_operation": getattr(consent, "operation", None),
        })

    # ---------------- WALLET ----------------
    elif action == "wallet":
        event.update({
            "wallet_id": getattr(wallet, "wallet_id", None),
            "wallet_action": getattr(wallet, "wallet_action", None),
        })

    return event