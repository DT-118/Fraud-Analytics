"""
profile_api.py

REST endpoints for dynamic risk profile queries.

  GET /v2/profile/{suid}
      Returns the full risk profile for a subject (composite + per-service).
      404 if the subject has never been scored.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
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
    """
    if not suid or len(suid) > 128 or "\x00" in suid:
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
        code = exc.args[0] if exc.args else None
        code_text = code.value if isinstance(code, ErrorCode) else "Internal error"
        logger.error("[PROFILE_API] %s: get_profile failed suid=%s", code_text, suid)
        raise HTTPException(status_code=500, detail=code_text) from exc

    except Exception as exc:
        logger.exception("[PROFILE_API] Unexpected error suid=%s", suid)
        raise HTTPException(status_code=500) from exc

    finally:
        release_db_connection(db)


@router.get("/services/{service}/profiles")
def get_service_profiles(
    service: str,
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, ge=1, le=100),
):
    """
    Service-wide risk profile roster — every subject_id's rolling_score,effective_score,
    event_count, last_risk_level for one service.
    """
    svc = service.upper()
    db = get_db_connection()
    try:
        return get_service_subject_profiles(db, svc, page=page, limit=limit)
    except RuntimeError as exc:
        code = exc.args[0] if exc.args else None
        status = 400 if code == ErrorCode.INVALID_REQUEST else 500
        raise HTTPException(
            status_code=status,
            detail=code.value if isinstance(code, ErrorCode) else "Internal error",
        ) from exc
    except Exception:
        logger.exception("[PROFILE_API] Unexpected error service=%s", svc)
        raise HTTPException(status_code=500)
    finally:
        release_db_connection(db)