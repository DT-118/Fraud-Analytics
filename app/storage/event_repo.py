from core.errors import ErrorCode
from core.logger import logger
from psycopg2.extras import Json
from core.constants import SERVICE_NAME


def insert_fraud_event(db_connection, context, source: str):
    """
    Persist the raw incoming fraud event into the fraud_events table.

    The unique event_id constraint makes the database write idempotent when
    the same event arrives more than once.
    """
    sql = """
    INSERT INTO fraud_events (
        schema_version, event_type, action_taxonomy, action_taxonomy_sub_method,
        event_id, correlation_id, transaction_id,
        session_id, request_id, subject_id,
        emirates_id_hash, role, exception_code,
        actor_type, actor_id, event_time,
        environment, service_name,
        security_payload,
        biometric_payload,
        document_payload,
        consent_payload,
        wallet_payload,
        biometric_method,
        source
    )
    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    ON CONFLICT (event_id) DO NOTHING
    """

    try:
        logger.info(
            "Inserting fraud event event_id=%s",
            context.event_id,
        )

        with db_connection.cursor() as cursor:
            cursor.execute(
                sql,
                (
                    "2.0",
                    f"{context.action_taxonomy.upper()}_EVENT",
                    context.action_taxonomy,
                    context.action_taxonomy_sub_method,
                    context.event_id,
                    context.correlation_id,
                    context.transaction_id,
                    context.session_id,
                    context.request_id,
                    context.subject_id,
                    context.emirates_id_hash,
                    context.role,
                    context.exception_code,
                    context.actor_type,
                    context.actor_id,
                    context.event_time,
                    context.environment,
                    SERVICE_NAME,
                    Json(context.security_payload.model_dump()),
                    (
                        Json(context.biometric_payload.model_dump())
                        if context.biometric_payload
                        else None
                    ),
                    (
                        Json(context.document_payload.model_dump())
                        if context.document_payload
                        else None
                    ),
                    (
                        Json(context.consent_payload.model_dump())
                        if context.consent_payload
                        else None
                    ),
                    (
                        Json(context.wallet_payload.model_dump())
                        if context.wallet_payload
                        else None
                    ),
                    context.biometric_method,
                    source,
                ),
            )
            inserted = cursor.rowcount == 1
        # False means this event_id already exists in fraud_events
        # (ON CONFLICT DO NOTHING skipped the insert).
        return inserted

    except Exception as exc:
        logger.exception(
            "FE-501:DATABASE_EVENT_INSERT_FAILED event_id=%s",
            context.event_id,
        )
        raise RuntimeError(ErrorCode.DATABASE_ERROR) from exc
