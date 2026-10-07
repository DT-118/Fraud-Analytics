from psycopg2.extras import Json
from core.constants import TAXONOMY_TO_SERVICE
from core.errors import ErrorCode
from core.logger import logger



def fetch_decision_for_event(db_connection, event_id: str) -> dict | None:
    """Rebuild the originally returned decision for an already-scored event."""
    sql = """
        SELECT d.subject_id, d.score, d.risk_level, d.triggered_rules,
               d.rule_weights, d.features, d.active_liveness_suggestion,
               d.exception_score, d.session_amplifier,
               e.correlation_id, e.transaction_id, e.biometric_method,d.pre_profile_score, d.profile_amplifier
        FROM fraud_decisions d
        JOIN fraud_events e ON e.event_id = d.event_id
        WHERE d.event_id = %s
    """
    try:
        with db_connection.cursor() as cursor:
            cursor.execute(sql, (event_id,))
            row = cursor.fetchone()
    except Exception as exc:
        logger.exception("FE-501:DATABASE_DECISION_FETCH_FAILED event_id=%s", event_id)
        raise RuntimeError(ErrorCode.DATABASE_ERROR) from exc

    if row is None:
        return None

    rule_weights = row[4] or {}
    return {
        "subject_id":        row[0],
        "event_id":          event_id,
        "correlation_id":    row[9],
        "transaction_id":    row[10],
        "biometric_method":  bool(row[11]),
        "features":          row[5] or {},
        "triggered_rules":   list(row[3] or []),
        "rule_weights":      rule_weights,
        "score":             int(row[1]),
        "exception_score":   float(row[7]) if row[7] is not None else None,
        "session_amplifier": float(row[8]) if row[8] is not None else None,
        "pre_profile_score": row[12],
        "profile_amplifier": float(row[13]) if row[13] is not None else None,
        "risk_level":        row[2],
        "active_liveness_suggestion": row[6],
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

    The unique event_id constraint makes the database write idempotent.
    If the same event_id is processed twice, the second insert is ignored.
    """
    fraud_type = TAXONOMY_TO_SERVICE.get(context.action_taxonomy, "UNKNOWN")

    sql = """
    INSERT INTO fraud_decisions (
        event_id, fraud_type, subject_id,
        emirates_id_hash, role, exception_code,
        score, risk_level, policy_action, active_liveness_suggestion,
        triggered_rules, rule_weights, features,
        exception_score, session_amplifier,
        pre_profile_score, profile_amplifier,
        source, config_version
    )
    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    ON CONFLICT (event_id) DO NOTHING
    """

    try:
        logger.info(
            "Inserting fraud decision event_id=%s",
            context.event_id,
        )

        triggered_rules = decision_payload["triggered_rules"]
        # psycopg2 expects a Python list for the PostgreSQL text[] column.
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
                    context.effective_role,
                    context.exception_code,
                    decision_payload["score"],
                    decision_payload["risk_level"],
                    None,
                    Json(decision_payload.get("active_liveness_suggestion")),
                    triggered_rules,
                    Json(decision_payload.get("rule_weights", {})),
                    Json(decision_payload["features"]),
                    decision_payload.get("exception_score"),
                    decision_payload.get("session_amplifier"),
                    decision_payload.get("pre_profile_score"),
                    decision_payload.get("profile_amplifier"),
                    source,
                    config_version,
                ),
            )

    except Exception as exc:
        logger.exception(
            "FE-501:DATABASE_DECISION_INSERT_FAILED event_id=%s",
            context.event_id,
        )
        raise RuntimeError(ErrorCode.DATABASE_ERROR) from exc