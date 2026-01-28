from psycopg2.extras import Json
from core.errors import ErrorCode
from core.logger import logger


def insert_fraud_decision(
    db_connection,
    context,
    decision_payload,
    source: str,
    config_version: str,
):
    """
    Persist the fraud decision outcome into the fraud_decisions table.

    Stores scoring result, triggered rules, extracted features,
    and configuration version used for evaluation.
    """
    fraud_type_by_action = {
        "login": "AUTH",
        "enroll": "ENROLL",
        "consent": "CONSENT",
        "wallet": "WALLET",
    }

    fraud_type = fraud_type_by_action.get(context.action_taxonomy, "UNKNOWN")

    sql = """
    INSERT INTO fraud_decisions (
        event_id, fraud_type, subject_id,
        score, risk_level, policy_action,
        triggered_rules, features,
        source, config_version
    )
    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """

    try:
        logger.info(f"Inserting fraud decision for event_id={context.event_id}")
        print("[DB] Inserting fraud decision")

        with db_connection.cursor() as cursor:
            cursor.execute(
                sql,
                (
                    context.event_id,
                    fraud_type,
                    context.subject_id,
                    decision_payload["score"],
                    decision_payload["risk_level"],
                    "no",
                    decision_payload["triggered_rules"],
                    Json(decision_payload["features"]),
                    source,
                    config_version,
                ),
            )

    except Exception as exc:
        logger.exception("FE-501:DATABASE_DECISION_INSERT_FAILED")
        print("[DB ERROR] Failed to insert fraud decision:", exc)
        raise RuntimeError(ErrorCode.DB_ERROR)
