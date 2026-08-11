"""
profile_api.py

REST endpoints for dynamic risk profile queries (Phase 3).

  GET /v2/profile/{suid}
      Returns the full risk profile for a subject (composite + per-service).
      404 if the subject has never been scored.
"""

from fastapi import APIRouter, Depends, HTTPException

from core.auth import require_api_key
from core.errors import ErrorCode
from core.logger import logger
from service.profile_service import get_risk_profile, get_service_subject_profiles
from storage.db import get_db_connection, release_db_connection

router = APIRouter(prefix="/v2", tags=["Risk Profiles"], dependencies=[Depends(require_api_key)])


@router.get("/profile/{suid}")
def get_profile(suid: str):
    """
    Retrieve the dynamic risk profile for a given SUID.

    Response shape:
      {
        "subject_id": "...",
        "identity_profile": {
          "composite_score": 42.5,
          "service_scores": { "AUTH": 55.0, "WALLET": 30.0, ... },
          "cross_service_flag": false,
          "cross_service_flag_reason": null,
          "cross_service_flag_at": null,
          "total_events": 17,
          "highest_risk_level": "MEDIUM",
          "updated_at": "2026-06-01T12:34:56+00:00"
        },
        "service_profiles": [
          {
            "service": "AUTH",
            "rolling_score": 55.0,
            "event_count": 12,
            "last_event_id": "...",
            "last_event_time": "...",
            "last_risk_level": "MEDIUM",
            "last_action_taken": "STEP_UP",
            "updated_at": "..."
          },
          ...
        ]
      }
    """
    if not suid or len(suid) > 128:
        raise HTTPException(status_code=400, detail="Invalid suid")

    db = get_db_connection()
    try:
        profile = get_risk_profile(db, suid)

        if profile is None:
            raise HTTPException(
                status_code=404,
                detail=f"No risk profile found for subject_id={suid}",
            )

        return profile

    except HTTPException:
        raise

    except RuntimeError as exc:
        error_code = str(exc)
        logger.error("[PROFILE_API] %s: get_profile failed suid=%s", error_code, suid)
        raise HTTPException(status_code=500, detail=error_code) from exc

    except Exception as exc:
        logger.exception("[PROFILE_API] Unexpected error suid=%s", suid)
        raise HTTPException(status_code=500) from exc

    finally:
        release_db_connection(db)


@router.get("/services/{service}/profiles")
def get_service_profiles(service: str, page: int = 1, limit: int = 50):
    """
    Service-wide risk profile roster — every subject_id's rolling_score,
    event_count, last_risk_level, last_action_taken for one service.
    """
    svc = service.upper()
    db = get_db_connection()
    try:
        return get_service_subject_profiles(db, svc, page=page, limit=limit)
    except RuntimeError as exc:
        error_code = str(exc)
        status = 400 if error_code == ErrorCode.INVALID_REQUEST else 500
        raise HTTPException(status_code=status, detail=error_code) from exc
    except Exception:
        logger.exception("[PROFILE_API] Unexpected error service=%s", svc)
        raise HTTPException(status_code=500)
    finally:
        release_db_connection(db)