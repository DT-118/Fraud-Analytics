from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator, ConfigDict
from core.auth import require_api_key
from core.constants import VALID_SERVICES
from core.ids import normalize_event_id
from core.logger import logger
from core.responses import success_response
from storage.db import get_db_connection, release_db_connection
from storage.action_storing_repo import insert_action_outcome

router = APIRouter(
    prefix="/fraud-analytics-backend/v2/actions",
    tags=["Service Actions"],
)


class ActionOutcomeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    event_id: str = Field(..., min_length=1)
    subject_id: str | None = Field(default=None, min_length=1, max_length=128)
    service: str | None = Field(default=None, min_length=1)
    action: str = Field(..., min_length=1, max_length=64)

    @field_validator("subject_id", "action")
    @classmethod
    def no_control_chars(cls, v):
        if v is not None and any(ch in v for ch in ("\n", "\r", "\x00")):
            raise ValueError("must not contain control characters")
        return v

    @field_validator("action")
    @classmethod
    def action_upper(cls, v):
        return v.upper()   # optional, keeps dashboards consistent

    @field_validator("service")
    @classmethod
    def service_valid(cls, v):
        if v is None:
            return v
        v = v.upper()
        if v not in VALID_SERVICES:
            raise ValueError(f"service must be one of {sorted(VALID_SERVICES)}")
        return v

    @field_validator("event_id")
    @classmethod
    def event_id_valid(cls, v):
        return normalize_event_id(v)


@router.post("", status_code=status.HTTP_200_OK)
def record_action_outcome(
    payload: ActionOutcomeRequest,
    _: str = Depends(require_api_key),
):
    """
    Record the action actually applied by the originating service for a
    previously scored fraud event.

    Only event_id and action are required. subject_id and service are taken
    from the stored event, never from the request. If the caller sends them
    anyway, they must match the event, otherwise the request is rejected with
    409 and nothing is written. Unknown event_id returns 404.
    """

    db_connection = get_db_connection()

    try:
        result = insert_action_outcome(db_connection, payload.event_id, payload.action)
        if result is None:
            db_connection.rollback()
            raise HTTPException(status_code=404, detail="event_id not found")

        if (
            (payload.subject_id is not None and payload.subject_id != result["subject_id"])
            or (payload.service is not None and payload.service != result["service"])
        ):
            db_connection.rollback()
            raise HTTPException(
                status_code=409,
                detail="subject_id/service do not match the event",
            )

        db_connection.commit()
        return success_response({
            "event_id": payload.event_id,
            "subject_id": result["subject_id"],
            "service": result["service"],
            "action": payload.action,
            "recorded": True,
            "id": result["id"],
            "created_at": result["created_at"],
            "updated_at": result["updated_at"],
        })

    except HTTPException:
        db_connection.rollback()
        raise

    except Exception:
        db_connection.rollback()
        logger.exception("record_action_outcome failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to record service action",
        )

    finally:
        release_db_connection(db_connection)