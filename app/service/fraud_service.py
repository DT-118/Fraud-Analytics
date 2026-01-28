"""
fraud_service.py

Service layer responsible for executing end-to-end fraud processing.
"""

from core.context import Context
from rules.engine import load_rules, run_rules
from scoring.engine import load_scores, aggregate_score, classify_risk
from features.auth_features import build_auth_features
from features.live_features import build_liveness_features
from features.enroll_features import build_enroll_features
from features.consent_features import build_consent_features
from features.wallet_features import build_wallet_features
from features.auth_trust import record_recent_successful_authentication
from storage.event_repo import insert_fraud_event
from storage.decision_repo import insert_fraud_decision
from core.errors import ErrorCode
from core.logger import logger

# Rule paths
AUTH_RULES_PATH = "rules/auth/rules.yaml"
ENROLL_RULES_PATH = "rules/enroll/rules.yaml"
CONSENT_RULES_PATH = "rules/consent/rules.yaml"
WALLET_RULES_PATH = "rules/wallet/rules.yaml"

# Unified scoring config
SCORES_CONFIG_PATH = "scoring/scores.yaml"


def handle_fraud_event(
    event_context: Context,
    *,
    db_connection,
    source: str,
    config_version: str,
) -> dict:
    """
    Execute end-to-end fraud processing for a single event.

    Flow:
    - Persist raw event
    - Build features
    - Run rules
    - Aggregate score
    - Classify risk
    - Persist decision

    Returns final fraud decision.
    """
    try:
        print("[SERVICE] Processing fraud event")
        logger.info("Fraud event processing started")

        # ---------------- Persist raw event ----------------
        insert_fraud_event(db_connection, event_context, source=source)

        # ---------------- Feature extraction ----------------
        if event_context.action_taxonomy == "login":
            auth_features = build_auth_features(event_context)
            live_features = build_liveness_features(event_context)
            record_recent_successful_authentication(event_context)

            feature_values = {**auth_features, **live_features}
            rules_config = load_rules(AUTH_RULES_PATH)

        elif event_context.action_taxonomy == "enroll":
            feature_values = build_enroll_features(event_context)
            rules_config = load_rules(ENROLL_RULES_PATH)

        elif event_context.action_taxonomy == "consent":
            feature_values = build_consent_features(event_context)
            rules_config = load_rules(CONSENT_RULES_PATH)

        elif event_context.action_taxonomy == "wallet":
            feature_values = build_wallet_features(event_context)
            rules_config = load_rules(WALLET_RULES_PATH)

        else:
            print("[SERVICE][ERROR] Unsupported action taxonomy")
            logger.error(f"{ErrorCode.INVALID_REQUEST}: Unsupported action_taxonomy")
            raise RuntimeError(ErrorCode.INVALID_REQUEST)

        # ---------------- Rule evaluation ----------------
        triggered_rules = run_rules(rules_config, feature_values)

        # ---------------- Scoring ----------------
        scoring_config = load_scores(SCORES_CONFIG_PATH)
        total_score = aggregate_score(triggered_rules)
        risk_level = classify_risk(total_score, scoring_config)

        decision = {
            "subject_id": event_context.subject_id,
            "features": feature_values,
            "triggered_rules": [r["rule_id"] for r in triggered_rules],
            "score": total_score,
            "risk_level": risk_level,
        }

        # ---------------- Persist decision ----------------
        insert_fraud_decision(
            db_connection,
            event_context,
            decision,
            source=source,
            config_version=config_version,
        )

        print("[SERVICE] Fraud processing completed successfully")
        logger.info("Fraud event processed successfully")

        return decision

    except RuntimeError:
        # Already classified
        raise

    except Exception as exc:
        print("[SERVICE][ERROR] Fraud processing failed")
        logger.exception(f"{ErrorCode.INTERNAL_ERROR}: Fraud service failure")
        raise RuntimeError(ErrorCode.INTERNAL_ERROR) from exc
