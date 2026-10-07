"""
biometric_features.py

Biometric feature extraction with Redis-backed pattern tracking.
Consolidates liveness spoof tracking + face UDB mismatch tracking.

Works for ALL taxonomies: AUTH, WALLET, LOGIN, CONSENT

Redis state:
  biometric:spoof_attempts:{subject_id} - spoof count in window
  biometric:missing_liveness:{subject_id} - missing liveness count in window
  biometric:face_udb_mismatch:{subject_id} - face mismatch count in window

Configuration:
  config/redis_ttl.yml for retention windows

"""

from __future__ import annotations
from pathlib import Path
from core.config_loader import HotConfig
from core.context import Context
from core.errors import ErrorCode
from core.logger import logger
from rules.engine import is_rule_active
from storage.redis_client import redis_client
from storage.redis_utils import touch
from core.constants import TAXONOMY_TO_SERVICE   


_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"

# Redis behavioral-state retention. Values are expressed in seconds.
_REDIS_TTL_CONFIG = HotConfig(_CONFIG_DIR / "redis_ttl.yml")

# ============================================================================
# Helper function 
# ============================================================================

def _redis_ttl() -> dict:
    """Return the current Redis feature-retention configuration."""
    return _REDIS_TTL_CONFIG.get()


# ============================================================================
# BIOMETRIC_SPOOF_DETECTED - Count spoof attempts 
# ============================================================================

def build_spoof_detection_feature(
    context: Context,
    rule_overrides: dict,
) -> int:
    """
    Count recent biometric attempts with an explicit liveness spoof result.
    
    Works for ALL taxonomies.
    """
    try:
        if not is_rule_active(
            "BIOMETRIC_SPOOF_DETECTED",
            TAXONOMY_TO_SERVICE.get(context.action_taxonomy, "AUTH"),
            rule_overrides,
        ):
            return 0

        biometric_payload = context.biometric_payload
        if not biometric_payload:
            return 0

        if not biometric_payload.liveness_required:
            return 0

        if biometric_payload.liveness_result != "SPOOF":
            return 0

        redis_key = f"biometric:spoof_attempts:{context.subject_id}"
        attempt_window_seconds = int(_redis_ttl()["biometric"]["spoof_window"])
        

        spoof_count = redis_client.incr(redis_key)
        touch(redis_key, attempt_window_seconds)

        return int(spoof_count)

    except Exception as exc:
        logger.exception(
            "%s: BIOMETRIC_SPOOF_DETECTED Redis failure subject_id=%s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
        )
        raise RuntimeError(ErrorCode.REDIS_ERROR) from exc


# ===============================================================================
# LIVENESS_RESULT_MISSING - Missing liveness result but liveness_required = True
# ===============================================================================

def build_missing_liveness_feature(
    context: Context,
    rule_overrides: dict,
) -> int:
    """
    Count attempts where required liveness verification was not provided.
    
    Works for ALL taxonomies (not AUTH-only).
    Replaces: build_live02_missing_liveness_feature from live_features.py
    """
    try:
        if not is_rule_active(
            "LIVENESS_RESULT_MISSING",
            TAXONOMY_TO_SERVICE.get(context.action_taxonomy, "AUTH"),   
            rule_overrides,
        ):
            return 0

        biometric_payload = context.biometric_payload
        if not biometric_payload:
            return 0

        return int(
            biometric_payload.liveness_required
            and biometric_payload.liveness_result is None
        )

    except Exception as exc:
        logger.exception(
            "%s: LIVENESS_RESULT_MISSING feature failure subject_id=%s",
            ErrorCode.INTERNAL_ERROR,
            context.subject_id,
        )
        raise RuntimeError(ErrorCode.INTERNAL_ERROR) from exc


# ============================================================================
# UDB_FACE_MISMATCH - Count face mismatches
# ============================================================================

def build_face_udb_mismatch_feature(
    context: Context,
    rule_overrides: dict,
) -> int:
    """
    Count biometric face-to-UDB mismatches within the configured retention window.
    
    Note: Uses biometric_payload.face_udb_matched (moved from document_payload)
    """
    try:
        if not is_rule_active(
            "UDB_FACE_MISMATCH",
            TAXONOMY_TO_SERVICE.get(context.action_taxonomy, "AUTH"),
            rule_overrides,
        ):
            return 0

        biometric_payload = context.biometric_payload
        if not biometric_payload or biometric_payload.face_udb_matched is not False:
            return 0

        redis_key = f"biometric:face_udb_mismatch:{context.subject_id}"
        window_seconds = int(_redis_ttl()["biometric"]["face_mismatch_window"])

        mismatch_count = redis_client.incr(redis_key)
        touch(redis_key, window_seconds)

        return int(mismatch_count)

    except Exception as exc:
        logger.exception(
            "%s: UDB_FACE_MISMATCH Redis failure subject_id=%s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
        )
        raise RuntimeError(ErrorCode.REDIS_ERROR) from exc


# ============================================================================
# Main builder
# ============================================================================

def build_biometric_features(
    context: Context,
    rule_overrides: dict,
) -> dict:
    """
    Build all biometric features from payload with Redis-tracked patterns.
    
    Works for ALL taxonomies: AUTH, WALLET, LOGIN, CONSENT
    
    Returns:
        dict with Redis-tracked feature counts
    """
    features = {}

    if not context.biometric_payload:
        return features

    # Spoof detection (Redis-tracked count)
    features["spoof_detected"] = build_spoof_detection_feature(context, rule_overrides)

    # Missing liveness (immediate signal, 0 or 1)
    features["missing_liveness"] = build_missing_liveness_feature(context, rule_overrides)

    # Face UDB mismatch (Redis-tracked count)
    features["face_udb_mismatch_count"] = build_face_udb_mismatch_feature(context, rule_overrides)

    return features