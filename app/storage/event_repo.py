from core.errors import ErrorCode
from core.logger import logger
from psycopg2.extras import Json


def insert_fraud_event(db_connection, context, source: str):
    """
    Persist the raw incoming fraud event into the fraud_events table.

    Stores the full normalized Context payload for audit,
    replay, analytics, and offline learning.
    """
    sql = """
    INSERT INTO fraud_events (
        schema_version, event_type, action,
        event_id, correlation_id, transaction_id,
        session_id, request_id, subject_id,
        actor_type, actor_id, event_time,
        environment, service_name,
        security_payload,
        biometric_payload,
        document_payload,
        consent_payload,
        wallet_payload,
        source
    )
    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """

    try:
        logger.info(f"Inserting fraud event event_id={context.event_id}")
        print("[DB] Inserting fraud event")

        with db_connection.cursor() as cursor:
            cursor.execute(
                sql,
                (
                    "1.0",
                    f"{context.action_taxonomy.upper()}_EVENT",
                    context.action_taxonomy,
                    context.event_id,
                    context.correlation_id,
                    context.transaction_id,
                    context.session_id,
                    context.request_id,
                    context.subject_id,
                    context.actor_type,
                    context.actor_id,
                    context.event_time,
                    context.environment,
                    "fraud-engine",
                    Json(context.security_payload.dict()),
                    (
                        Json(context.biometric_payload.dict())
                        if context.biometric_payload
                        else None
                    ),
                    (
                        Json(context.document_payload.dict())
                        if context.document_payload
                        else None
                    ),
                    (
                        Json(context.consent_payload.dict())
                        if context.consent_payload
                        else None
                    ),
                    (
                        Json(context.wallet_payload.dict())
                        if context.wallet_payload
                        else None
                    ),
                    source,
                ),
            )

    except Exception as exc:
        logger.exception("FE-501:DATABASE_EVENT_INSERT_FAILED")
        print("[DB ERROR] Failed to insert fraud event:", exc)
        raise RuntimeError(ErrorCode.DB_ERROR) from exc
