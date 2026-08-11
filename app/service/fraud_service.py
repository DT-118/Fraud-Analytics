"""
fraud_service.py

Service layer responsible for executing end-to-end fraud processing.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from core.constants import TAXONOMY_TO_SERVICE
from core.context import Context
from core.errors import ErrorCode
from core.idempotency import is_duplicate
from core.logger import logger
from features.auth_features import build_auth_features
from features.baseline_features import build_baseline_features
from features.consent_features import build_consent_features
from features.device_features import build_device_trust_features
from features.enroll_features import build_enroll_features
from features.geo_features import build_geo_features
from features.live_features import build_liveness_features
from features.wallet_features import build_wallet_features
from rules.engine import apply_chains, load_rules, run_rules
from storage.baseline_repo import fetch_baselines, fetch_service_tolerance, upsert_baselines_for_event
from scoring.engine import apply_session_amplifier, compute_event_score, classify_risk, load_scores
#from service.action_engine import resolve_action
from service.ip_reputation import build_ip_reputation_features
from service.profile_service import update_risk_profile
from service.session_service import get_session_amplifier, persist_session_summary, update_session_state
from storage.db import get_db_connection, release_db_connection
from storage.decision_repo import insert_fraud_decision
from storage.event_repo import insert_fraud_event
from storage.profile_repo import fetch_cross_service_flag

_APP_DIR = Path(__file__).parent.parent

# Bounded pool for fire-and-forget profile/baseline updates.
_async_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="fraud-async")

AUTH_RULES_PATH    = str(_APP_DIR / "rules/auth/rules.yaml")
ENROLL_RULES_PATH  = str(_APP_DIR / "rules/enroll/rules.yaml")
CONSENT_RULES_PATH = str(_APP_DIR / "rules/consent/rules.yaml")
WALLET_RULES_PATH  = str(_APP_DIR / "rules/wallet/rules.yaml")

SCORES_CONFIG_PATH = str(_APP_DIR / "scoring/scores.yaml")


def _update_profile_async(
    subject_id: str,
    action_taxonomy: str,
    final_score: int,
    event_id: str,
    event_time: datetime,
    risk_level: str,
    #action_taken: str,
) -> None:
    db = None
    try:
        db = get_db_connection()
        update_risk_profile(
            db,
            subject_id=subject_id,
            action_taxonomy=action_taxonomy,
            final_score=final_score,
            event_id=event_id,
            event_time=event_time,
            risk_level=risk_level,
            #action_taken=action_taken,
        )
        db.commit()
        logger.info(
            "[SERVICE] Profile updated subject_id=%s taxonomy=%s score=%d risk=%s",
            subject_id, action_taxonomy, final_score, risk_level,
        )
    except Exception as exc:
        if db:
            db.rollback()
        logger.warning(
            "[SERVICE] Async profile update failed subject_id=%s: %s", subject_id, exc
        )
    finally:
        if db:
            release_db_connection(db)


def _update_baseline_async(
    subject_id: str,
    service: str,
    feature_values: dict,
) -> None:
    db = None
    try:
        db = get_db_connection()
        upsert_baselines_for_event(db, subject_id, service, feature_values)
        db.commit()
    except Exception as exc:
        if db:
            db.rollback()
        logger.warning(
            "[SERVICE] Async baseline update failed subject_id=%s service=%s: %s",
            subject_id, service, exc,
        )
    finally:
        if db:
            release_db_connection(db)


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
    1.  Idempotency check — skip if already processed
    2.  Persist raw event
    3.  Build features (Redis behavioral windows)
    4.  Load + evaluate rules (in-memory cached YAML)
    5.  Compute weighted score with role modifiers + biometric penalty + exception amplifier
    6.  Classify risk band
    7.  Resolve enforcement action from service_actions.yaml
    8.  Persist decision
    9. Return decision to caller
    """
    try:
        logger.info("[SERVICE] Processing event_id=%s taxonomy=%s role=%s",
                    event_context.event_id,
                    event_context.action_taxonomy,
                    event_context.role)

        # ---------------- Idempotency guard ----------------
        if is_duplicate(event_context.event_id, event_context.action_taxonomy):
            logger.warning("[SERVICE] Duplicate event_id=%s — skipping",
                           event_context.event_id)
            return {
                "subject_id":      event_context.subject_id,
                "event_id":        event_context.event_id,
                "score":           0,
                "risk_level":      "NORISK",
                #"action_taken":    "ALLOW",
                "triggered_rules": [],
                "features":        {},
                "duplicate":       True,
            }

        # ---------------- Persist raw event ----------------
        insert_fraud_event(db_connection, event_context, source=source)

        # ---------------- Feature extraction (service-specific) ----------------
        service_key = TAXONOMY_TO_SERVICE.get(event_context.action_taxonomy, "AUTH")

        if event_context.action_taxonomy == "login":
            feature_values = {
                **build_auth_features(event_context),
                **build_liveness_features(event_context),
            }
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
            logger.error("%s: Unsupported action_taxonomy=%s",
                         ErrorCode.INVALID_REQUEST, event_context.action_taxonomy)
            raise RuntimeError(ErrorCode.INVALID_REQUEST)

        # ---------------- Device trust + IP reputation (all services) ----------------
        feature_values.update(build_device_trust_features(event_context))
        feature_values.update(
            build_ip_reputation_features(event_context.security_payload.src_ip)
        )

        # ---------------- UAE territorial boundary check (all services) ----------------
        feature_values.update(build_geo_features(event_context, service=service_key))

        # ---------------- Phase 5: Personal baseline deviation (z-score) ----------------
        try:
            baselines = fetch_baselines(db_connection, event_context.subject_id, service_key)
            tolerance_config = fetch_service_tolerance(db_connection, service_key)
            feature_values.update(
                build_baseline_features(feature_values, baselines, tolerance_config)
            )
        except Exception as _bl_err:
            logger.warning("[SERVICE] Baseline features skipped (fail-open): %s", _bl_err)

        # ---------------- Rule evaluation ----------------
        triggered_rules = run_rules(rules_config, feature_values, service_key)

        # ---------------- Rule chaining ----------------
        triggered_rules = apply_chains(rules_config, triggered_rules, role=event_context.role)

        # ---------------- Scoring ----------------
        scoring_output = compute_event_score(
            triggered_rules=triggered_rules,
            role=event_context.role,
            exception_code=event_context.exception_code,
            #biometric_payload=event_context.biometric_payload,
            service=service_key,
        )

        # ---------------- Session amplifier ----------------
        session_amplifier = get_session_amplifier(
            event_context.session_id,
            action_taxonomy=event_context.action_taxonomy,
        )
        final_score = apply_session_amplifier(scoring_output["final_score"], session_amplifier)
        raw_score   = scoring_output["raw_score"]

        scoring_config = load_scores(SCORES_CONFIG_PATH)
        risk_level     = classify_risk(final_score, scoring_config)

        # ---------------- Action resolution (with cross-service flag) ----------------
        cross_service_flagged = fetch_cross_service_flag(db_connection, event_context.subject_id)
        # action_taken = resolve_action(
        #     event_context.action_taxonomy,
        #     risk_level,
        #     cross_service_flagged=cross_service_flagged,
        # )

        decision = {
            "subject_id":          event_context.subject_id,
            "event_id":            event_context.event_id,
            "correlation_id":      event_context.correlation_id,
            "transaction_id":      event_context.transaction_id,
            "features":            feature_values,
            "triggered_rules":     [r["rule_id"] for r in triggered_rules],
            "rule_weights":        scoring_output["role_adjusted_weights"],
            "score":               final_score,
            "raw_score":           raw_score,
            #"biometric_penalty":   scoring_output["biometric_penalty"],
            "exception_amplifier": scoring_output["exception_amplifier"],
            "session_amplifier":   session_amplifier,
            "risk_level":          risk_level,
            #"action_taken":        action_taken,
        }

        # ---------------- Persist decision ----------------
        insert_fraud_decision(
            db_connection,
            event_context,
            decision,
            source=source,
            config_version=config_version,
        )

        # ---------------- Update session state ----------------
        update_session_state(
            event_context.session_id,
            event_id=event_context.event_id,
            score=final_score,
            risk_level=risk_level,
            action_taxonomy=event_context.action_taxonomy,
        )

        # Best-effort session DB sync
        try:
            persist_session_summary(
                db_connection,
                session_id=event_context.session_id,
                subject_id=event_context.subject_id,
            )
        except Exception:
            pass

        # ---------------- Update dynamic risk profile (async) ----------------
        _async_executor.submit(
            _update_profile_async,
            event_context.subject_id,
            event_context.action_taxonomy,
            final_score,
            event_context.event_id,
            event_context.event_time,
            risk_level,
            #action_taken,
        )

        # ---------------- Update personal feature baselines (async) ----------------
        # feature_values includes derived z-score features; upsert_baselines_for_event
        # filters these out internally before writing.
        _async_executor.submit(
            _update_baseline_async,
            event_context.subject_id,
            service_key,
            feature_values,
        )

        logger.info(
            "[SERVICE] Completed event_id=%s score=%d raw=%d risk=%s",
            #"[SERVICE] Completed event_id=%s score=%d raw=%d risk=%s action=%s",   # ← original, action removed
            event_context.event_id, final_score, raw_score, risk_level,
            #action_taken,   # ← comment out
        )

        return decision

    except RuntimeError:
        raise

    except Exception as exc:
        logger.exception("%s: Fraud service failure event_id=%s",
                         ErrorCode.INTERNAL_ERROR, event_context.event_id)
        raise RuntimeError(ErrorCode.INTERNAL_ERROR) from exc
