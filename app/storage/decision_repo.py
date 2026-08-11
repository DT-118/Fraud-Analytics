from core.errors import ErrorCode
from core.logger import logger
from psycopg2.extras import Json

_FRAUD_TYPE_MAP = {
    "login":   "AUTH",
    "enroll":  "ENROLL",
    "consent": "CONSENT",
    "wallet":  "WALLET",
}


def insert_fraud_decision(
    db_connection,
    context,
    decision_payload,
    source: str,
    config_version: str,
):
    """
    Persist the fraud decision outcome into the fraud_decisions table.

    ON CONFLICT DO NOTHING provides idempotency: if Redis was temporarily
    down and the same event_id is processed twice, the second insert is
    silently dropped (UNIQUE constraint on event_id added in phase6_migration).
    """
    fraud_type = _FRAUD_TYPE_MAP.get(context.action_taxonomy, "UNKNOWN")

    sql = """
    INSERT INTO fraud_decisions (
        event_id, fraud_type, subject_id,
        emirates_id_hash, role, exception_code,
        score, risk_level, policy_action,
        triggered_rules, rule_weights, features,
        source, config_version
    )
    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    ON CONFLICT (event_id) DO NOTHING
    """

    try:
        logger.info("Inserting fraud decision event_id=%s",
            context.event_id)
        #logger.info("Inserting fraud decision event_id=%s action=%s",
        #            context.event_id, decision_payload.get("action_taken"))   # ← original

        triggered_rules = decision_payload["triggered_rules"]
        # psycopg2 needs a list for text[] — ensure it's a plain list
        if not isinstance(triggered_rules, list):
            triggered_rules = list(triggered_rules)

    
        with db_connection.cursor() as cursor:
            cursor.execute(
                sql,
                (
                    context.event_id,
                    fraud_type,
                    context.subject_id,
                    context.emirates_id_hash,
                    context.role,
                    context.exception_code,
                    decision_payload["score"],
                    decision_payload["risk_level"],
                    None,
                    #decision_payload["action_taken"],
                    triggered_rules,
                    Json(decision_payload.get("rule_weights", {})),
                    Json(decision_payload["features"]),
                    source,
                    config_version,
                ),
            )

    except Exception as exc:
        logger.exception("FE-501:DATABASE_DECISION_INSERT_FAILED event_id=%s", context.event_id)
        raise RuntimeError(ErrorCode.DB_ERROR) from exc
