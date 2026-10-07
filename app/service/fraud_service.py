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
from core.idempotency import is_duplicate, release_idempotency
from core.logger import logger
from features.auth_features import build_auth_features
from features.baseline_features import build_baseline_features
from features.consent_features import build_consent_features
from features.device_features import build_device_shared_features, build_device_switch_features, build_device_switch_velocity_feature
from features.login_features import build_login_features
from features.geo_features import build_geo_features
from features.biometric_features import build_biometric_features
from features.wallet_features import build_wallet_features
from features.ip_features import build_ip_reputation_features
from features.odd_hour_activity_feature import build_odd_hours_feature
from rules.engine import apply_chains, load_rules, run_rules, fetch_rule_overrides
from storage.baseline_repo import fetch_baselines, fetch_service_tolerance, upsert_baselines_for_event
from scoring.engine import apply_session_amplifier, compute_event_score, classify_risk, load_scores
from scoring.profile_amplifier import get_profile_amplifier
from service.profile_service import update_risk_profile
from service.session_service import get_session_amplifier, persist_session_summary, update_session_state
from storage.db import get_db_connection, release_db_connection
from storage.decision_repo import fetch_decision_for_event, insert_fraud_decision
from storage.event_repo import insert_fraud_event
from storage.profile_repo import fetch_identity_profile

from service.liveness_suggestion import get_active_liveness_suggestion

_APP_DIR = Path(__file__).parent.parent

# Bounded pool for fire-and-forget profile/baseline updates.
_async_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="fraud-async")

AUTH_RULES_PATH    = str(_APP_DIR / "config/rules/auth_rules.yaml")
LOGIN_RULES_PATH   = str(_APP_DIR / "config/rules/login_rules.yaml")
CONSENT_RULES_PATH = str(_APP_DIR / "config/rules/consent_rules.yaml")
WALLET_RULES_PATH  = str(_APP_DIR / "config/rules/wallet_rules.yaml")
SCORES_CONFIG_PATH = str(_APP_DIR / "scoring/scores.yaml")


def shutdown_async_executor(wait: bool = True) -> None:
    """
    Drain the fire-and-forget profile/baseline update pool.

    MUST be called from api.py's lifespan shutdown phase BEFORE
    storage.db.close_pool(). Each background task (_update_profile_async /
    _update_baseline_async) borrows its own DB connection via
    get_db_connection() independently of the request that submitted it.
    Closing the connection pool while one of those tasks is still mid-write
    yanks a live connection out from under it — closeall() closes checked-out
    connections too, not just idle ones — which can drop the write and
    surface as a raw psycopg2 error in a background thread.

    wait=True (default) blocks until every currently running/queued task
    completes, and causes any further .submit() call to raise RuntimeError
    — which is intentional: nothing should be enqueuing new async DB work
    once shutdown has started.
    """
    logger.info("[SERVICE] Draining async executor before shutdown...")
    _async_executor.shutdown(wait=wait)
    logger.info("[SERVICE] Async executor drained")


def _update_profile_async(
    subject_id: str,
    action_taxonomy: str,
    final_score: int,
    event_id: str,
    event_time: datetime,
    risk_level: str,
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

def run_post_commit_tasks(tasks: list) -> None:
    """Fire deferred profile/baseline updates. Call ONLY after the DB commit succeeded."""
    for fn, args in tasks:
        try:
            _async_executor.submit(fn, *args)
        except Exception as exc:
            logger.warning("[SERVICE] post-commit task submit failed: %s", exc)


def handle_fraud_event(
    event_context: Context,
    *,
    db_connection,
    source: str,
    config_version: str,
    post_commit_tasks: list | None = None,
) -> dict:
    """
    Execute end-to-end fraud processing for a single event.

    Flow:
    1.  Idempotency check — skip if already processed
    2.  Persist raw event
    3.  Build features (Redis behavioral windows)
    4.  Load + evaluate rules (in-memory cached YAML)
    5.  Compute weighted score with role modifiers + exception scores 
    6.  Classify risk band
    7.  Suggest active liveness if necessary
    8.  Persist decision
    9.  Return decision to caller
    """
    claimed = False
    try:
        logger.info("[SERVICE] Processing event_id=%s taxonomy=%s role=%s",
                    event_context.event_id,
                    event_context.action_taxonomy,
                    event_context.effective_role)

        # ---------------- Idempotency guard ----------------
        if is_duplicate(event_context.event_id, event_context.action_taxonomy):
            logger.warning("[SERVICE] Duplicate event_id=%s — skipping",
                           event_context.event_id)
            return {
                "subject_id":      event_context.subject_id,
                "event_id":        event_context.event_id,
                "duplicate":       True,
            }
        claimed = True

        # ---------------- Persist raw event ----------------
        inserted = insert_fraud_event(db_connection, event_context, source=source)
        if not inserted:
            # Redis key had expired but the event was already processed.
            # Return what was stored; no features, scoring or profile updates run.
            # The Redis claim is kept, so repeats are caught at the first check again.
            logger.warning("[SERVICE] Duplicate event_id=%s found in DB — returning stored decision",
                           event_context.event_id)
            stored = fetch_decision_for_event(db_connection, event_context.event_id) or {
                "subject_id": event_context.subject_id,
                "event_id":   event_context.event_id,
            }
            stored["duplicate"] = True
            return stored

        # ---------------- Feature extraction ----------------
        rule_overrides = fetch_rule_overrides()
        service_key = TAXONOMY_TO_SERVICE.get(event_context.action_taxonomy, "AUTH")

        # ---- Generic, cross-service features first — no taxonomy branching needed ----
        feature_values: dict = {}
        feature_values.update(
            build_ip_reputation_features(event_context.security_payload.src_ip)
        )
        feature_values.update(build_device_shared_features(event_context, rule_overrides))
        device_switch_result = build_device_switch_features(event_context, rule_overrides)
        feature_values.update(device_switch_result)
        feature_values.update(
            build_device_switch_velocity_feature(event_context, rule_overrides, device_switch_result)
        )
        feature_values.update(
            build_geo_features(event_context, rule_overrides, service=service_key)
        )
        feature_values.update(
            build_odd_hours_feature(event_context, rule_overrides, service=service_key)
        )

        # ---- Service-specific features (taxonomy-dependent) ----
        if event_context.action_taxonomy == "auth":
            feature_values.update(build_auth_features(event_context, rule_overrides))
            rules_config = load_rules(AUTH_RULES_PATH)

        elif event_context.action_taxonomy == "login":
            feature_values.update(build_login_features(event_context, rule_overrides))
            rules_config = load_rules(LOGIN_RULES_PATH)

        elif event_context.action_taxonomy == "consent":
            feature_values.update(build_consent_features(event_context, rule_overrides))
            rules_config = load_rules(CONSENT_RULES_PATH)

        elif event_context.action_taxonomy == "wallet":
            feature_values.update(build_wallet_features(event_context, rule_overrides))
            rules_config = load_rules(WALLET_RULES_PATH)

        else:
            logger.error("%s: Unsupported action_taxonomy=%s",
                         ErrorCode.INVALID_REQUEST, event_context.action_taxonomy)
            raise RuntimeError(ErrorCode.INVALID_REQUEST)

        # ---------------- Biometric features (generic, cross-service) ----------------
        # Runs if the caller asserted biometric auth OR sent biometric payload data.
        # Using OR (not just the flag) means a tampered/lied flag doesn't bypass
        # detection — if real payload data is present, it still gets scored.
        if event_context.biometric_method or event_context.biometric_payload:
            feature_values.update(build_biometric_features(event_context, rule_overrides))

        # ---------------- Personal baseline deviation (z-score) ----------------
        try:
            baselines = fetch_baselines(db_connection, event_context.subject_id, service_key)
            tolerance_config = fetch_service_tolerance(db_connection, service_key)
            feature_values.update(
                build_baseline_features(feature_values, baselines, tolerance_config)
            )
        except Exception as _bl_err:
            logger.warning("[SERVICE] Baseline features skipped (fail-open): %s", _bl_err)


        # ---------------- Rule evaluation ----------------
        triggered_rules = run_rules(rules_config, feature_values, service_key,rule_overrides)

        # ---------------- Rule chaining ----------------
        triggered_rules = apply_chains(rules_config, triggered_rules)

        # ---------------- Scoring ----------------
        scoring_output = compute_event_score(
            triggered_rules=triggered_rules,
            role=event_context.effective_role,
            exception_code=event_context.exception_code,
            service=service_key,
        )


        # ---------------- Session + profile amplifiers ----------------
        identity_profile = fetch_identity_profile(db_connection, event_context.subject_id)

        session_amplifier = get_session_amplifier(event_context.session_id)
        pre_profile_score = apply_session_amplifier(scoring_output["final_score"], session_amplifier)

        scoring_config   = load_scores(SCORES_CONFIG_PATH)
        pre_profile_risk = classify_risk(pre_profile_score, scoring_config)

        profile_amplifier = get_profile_amplifier(identity_profile)
        final_score = min(100, int(pre_profile_score * profile_amplifier))
        risk_level  = classify_risk(final_score, scoring_config)
        raw_score   = scoring_output["raw_score"]

        #------------------ Active Liveness Suggestion --------- 
        active_liveness = get_active_liveness_suggestion(
            risk_level=risk_level,
            identity_profile=identity_profile,   # reuse, remove the later fetch
        )

        decision = {
            "subject_id":          event_context.subject_id,
            "event_id":            event_context.event_id,
            "correlation_id":      event_context.correlation_id,
            "transaction_id":      event_context.transaction_id,
            "biometric_method":    event_context.biometric_method,
            "features":            feature_values,
            "triggered_rules":     [r["rule_id"] for r in triggered_rules],
            "rule_weights":        scoring_output["role_adjusted_weights"],
            "score":               final_score,
            "exception_score":     scoring_output["exception_score"],
            "session_amplifier":   session_amplifier,
            "pre_profile_score":   pre_profile_score,
            "profile_amplifier":   profile_amplifier,
            "risk_level":          risk_level,
        }
        if active_liveness is not None:
            decision["active_liveness_suggestion"] = active_liveness

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
            score=pre_profile_score,
            risk_level=pre_profile_risk,
            event_time=event_context.event_time,
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
        # ---------------- Update personal feature baselines (async) ----------------
        # feature_values includes derived z-score features; upsert_baselines_for_event
        # filters these out internally before writing.
        def _defer(fn, *args):
            if post_commit_tasks is not None:
                post_commit_tasks.append((fn, args))
            else:
                _async_executor.submit(fn, *args)

        _defer(
            _update_profile_async,
            event_context.subject_id,
            event_context.action_taxonomy,
            pre_profile_score,          
            event_context.event_id,
            event_context.event_time,
            pre_profile_risk,          
        )
        _defer(_update_baseline_async, event_context.subject_id, service_key, feature_values)

        logger.info(
            "[SERVICE] Completed event_id=%s score=%d raw=%d risk=%s",
            event_context.event_id, final_score, raw_score, risk_level,
        )

        return decision

    except RuntimeError:
        if claimed:
            release_idempotency(event_context.event_id)
        raise

    except Exception as exc:
        if claimed:
            release_idempotency(event_context.event_id)
        logger.exception("%s: Fraud service failure event_id=%s",
                         ErrorCode.INTERNAL_ERROR, event_context.event_id)
        raise RuntimeError(ErrorCode.INTERNAL_ERROR) from exc