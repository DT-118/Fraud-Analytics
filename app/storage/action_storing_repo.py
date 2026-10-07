"""
Repository functions for persisting applied fraud actions.

Stores the action actually applied by the originating service for an
existing fraud event, in fraud_action_outcomes.

subject_id and service are never supplied by the caller. They are copied
from the stored fraud_events row (service is the upper-cased action
taxonomy, e.g. AUTH), so an outcome can't be attributed to the wrong
subject or service. They are stored on the outcome row so per-subject
queries ("every action applied for this user") need no join.

The write is an upsert keyed on the unique event_id. Calling it again for
the same event updates only the action and updated_at, so the latest
applied action wins and subject_id/service stay fixed.

If the event_id does not exist in fraud_events, nothing is written and
insert_action_outcome() returns None; the caller turns that into a 404.
The caller also owns commit/rollback.
"""

from __future__ import annotations
from core.errors import ErrorCode
from core.logger import logger

def insert_action_outcome(db_connection, event_id, action: str):
    """
    Upsert the applied action for an event. Returns a dict with id,
    subject_id, service, created_at, updated_at, or None if the event
    does not exist. Does not commit.
    """
    sql = """
        INSERT INTO fraud_action_outcomes (event_id, subject_id, service, action)
        SELECT e.event_id, e.subject_id, UPPER(e.action_taxonomy), %s
        FROM fraud_events e
        WHERE e.event_id = %s
        ON CONFLICT (event_id) DO UPDATE SET
            action     = EXCLUDED.action,
            updated_at = NOW()
        RETURNING id, subject_id, service, created_at, updated_at
    """
    try:
        with db_connection.cursor() as cursor:
            cursor.execute(sql, (action, event_id))
            row = cursor.fetchone()

        if row is None:
            return None  # event_id does not exist

        return {
            "id": str(row[0]),
            "subject_id": row[1],
            "service": row[2],
            "created_at": row[3],
            "updated_at": row[4],
        }
    except Exception as exc:
        logger.exception("FE-501:DATABASE_ACTION_OUTCOME_INSERT_FAILED event_id=%s", event_id)
        raise RuntimeError(ErrorCode.DATABASE_ERROR) from exc