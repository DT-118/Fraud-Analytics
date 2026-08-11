"""
profile_service.py

Service layer for dynamic risk profile management (Phase 3).

Responsibilities:
  1. Map action_taxonomy → canonical service key
  2. Upsert the per-service rolling risk score (time-decayed EWMA)
  3. Detect cross-service fraud patterns and set flag + reason
  4. Recompute and persist the composite identity risk profile
  5. Serve the profile GET endpoint by assembling the full response
"""

from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from core.config_loader import HotConfig
from core.constants import TAXONOMY_TO_SERVICE
from core.errors import ErrorCode
from core.logger import logger
from storage.profile_repo import (
    fetch_identity_profile,
    fetch_service_profiles,
    upsert_identity_profile,
    fetch_service_subject_profiles,
    upsert_service_profile,
)

_VALID_SERVICES = {"AUTH", "ENROLL", "CONSENT", "WALLET"}

_patterns_config = HotConfig(Path(__file__).parent.parent / "config/cross_service_patterns.yaml")


def _load_patterns() -> list[tuple]:
    """Parse cross_service_patterns.yaml into the internal tuple format."""
    cfg = _patterns_config.get()
    result = []
    for p in cfg.get("patterns", []):
        result.append((
            p["trigger_service"],
            set(p["trigger_risk_levels"]),
            p["target_service"],
            int(p["window_minutes"]),
            p["reason"],
        ))
    return result


def _detect_cross_service_flag(
    service_profiles: list[dict],
    current_service: str,
    current_risk_level: str,
) -> tuple[bool, Optional[str]]:
    """
    Scan the service profiles for cross-service fraud patterns.

    Returns (flag: bool, reason: str | None).
    Checks both directions:
      - Is the current event the *target* (i.e., the trigger service fired earlier)?
      - Is the current event the *trigger* (i.e., has the target service fired recently)?
    """
    profile_map: dict[str, dict] = {p["service"]: p for p in service_profiles}
    now = datetime.now(timezone.utc)
    patterns = _load_patterns()

    for trigger_svc, trigger_levels, target_svc, window_min, reason in patterns:
        # Pattern fires when current event is the TARGET and the trigger fired recently
        if current_service == target_svc:
            trigger_profile = profile_map.get(trigger_svc)
            if trigger_profile and trigger_profile["last_risk_level"] in trigger_levels:
                last_time_raw = trigger_profile.get("last_event_time")
                if last_time_raw:
                    last_time = (
                        datetime.fromisoformat(last_time_raw)
                        if isinstance(last_time_raw, str)
                        else last_time_raw
                    )
                    if last_time.tzinfo is None:
                        last_time = last_time.replace(tzinfo=timezone.utc)
                    if (now - last_time) <= timedelta(minutes=window_min):
                        return True, reason

        # Pattern also fires when current event is the TRIGGER and target fired recently
        if current_service == trigger_svc and current_risk_level in trigger_levels:
            target_profile = profile_map.get(target_svc)
            if target_profile and target_profile.get("last_event_time"):
                last_time_raw = target_profile["last_event_time"]
                last_time = (
                    datetime.fromisoformat(last_time_raw)
                    if isinstance(last_time_raw, str)
                    else last_time_raw
                )
                if last_time.tzinfo is None:
                    last_time = last_time.replace(tzinfo=timezone.utc)
                if (now - last_time) <= timedelta(minutes=window_min):
                    return True, reason

    return False, None


def update_risk_profile(
    db_connection,
    subject_id: str,
    action_taxonomy: str,
    final_score: int,
    event_id: str,
    event_time: datetime,
    risk_level: str,
    #action_taken: str,
) -> None:
    """
    Update both the per-service and composite identity risk profiles.

    Called by the profile_updater Kafka consumer after a scored event arrives.
    All DB writes happen within the caller's transaction scope.
    """
    try:
        service = TAXONOMY_TO_SERVICE.get(action_taxonomy)
        if not service:
            logger.warning("[PROFILE] Unknown action_taxonomy=%s — skipping profile update",
                           action_taxonomy)
            return

        # Step 1: Update per-service profile and get the new rolling score
        new_service_rolling = upsert_service_profile(
            db_connection,
            subject_id=subject_id,
            service=service,
            new_score=final_score,
            event_id=event_id,
            event_time=event_time,
            risk_level=risk_level,
            #action_taken=action_taken,
        )

        # Step 2: Fetch current state of all service profiles for cross-service check
        service_profiles = fetch_service_profiles(db_connection, subject_id)

        # Step 3: Detect cross-service fraud pattern
        cross_flag, cross_reason = _detect_cross_service_flag(
            service_profiles, service, risk_level
        )

        if cross_flag:
            logger.warning(
                "[PROFILE] Cross-service flag raised subject_id=%s reason=%s",
                subject_id, cross_reason,
            )

        # Step 4: Build the latest service score map for composite calculation
        # Merge the just-updated service score into the fetched map
        score_map: dict[str, float] = {
            p["service"]: p["rolling_score"] for p in service_profiles
        }
        score_map[service] = new_service_rolling  # ensure we use the freshest value

        # Step 5: Upsert composite identity profile
        composite = upsert_identity_profile(
            db_connection,
            subject_id=subject_id,
            service_scores=score_map,
            cross_service_flag=cross_flag,
            cross_service_flag_reason=cross_reason,
        )

        logger.info(
            "[PROFILE] Updated subject_id=%s service=%s service_score=%.2f composite=%.2f cross_flag=%s",
            subject_id, service, new_service_rolling, composite, cross_flag,
        )

    except RuntimeError:
        raise

    except Exception as exc:
        logger.exception("%s: update_risk_profile failed subject_id=%s",
                         ErrorCode.INTERNAL_ERROR, subject_id)
        raise RuntimeError(ErrorCode.INTERNAL_ERROR) from exc


def get_risk_profile(db_connection, subject_id: str) -> Optional[dict]:
    """
    Retrieve the full risk profile for a subject_id.

    Returns None if no profile exists yet (subject has not been scored).
    Response shape:
      {
        "subject_id": ...,
        "identity_profile": { composite_score, service_scores, cross_service_flag, ... },
        "service_profiles": [ { service, rolling_score, event_count, ... }, ... ],
      }
    """
    try:
        identity = fetch_identity_profile(db_connection, subject_id)
        services = fetch_service_profiles(db_connection, subject_id)

        if identity is None and not services:
            return None

        return {
            "subject_id":       subject_id,
            "identity_profile": identity,
            "service_profiles": services,
        }

    except RuntimeError:
        raise

    except Exception as exc:
        logger.exception("%s: get_risk_profile failed subject_id=%s",
                         ErrorCode.INTERNAL_ERROR, subject_id)
        raise RuntimeError(ErrorCode.INTERNAL_ERROR) from exc


def get_service_subject_profiles(db_connection, service: str, page: int = 1, limit: int = 50) -> dict:
    """
    Service-wide roster: all subjects' risk profile rows for one service.
    """
    if service not in _VALID_SERVICES:
        raise RuntimeError(ErrorCode.INVALID_REQUEST)

    try:
        return fetch_service_subject_profiles(db_connection, service=service, page=page, limit=limit)
    except RuntimeError:
        raise
    except Exception as exc:
        logger.exception("%s: get_service_subject_profiles failed service=%s",
                         ErrorCode.INTERNAL_ERROR, service)
        raise RuntimeError(ErrorCode.INTERNAL_ERROR) from exc
