"""
session_service.py

Session-level fraud intelligence.

A session groups multiple events that share the same session_id.
When a session accumulates HIGH or CRITICAL events, subsequent events
in that session carry elevated risk — the session amplifier multiplies
the final score before risk classification.

Session TTL is per-service (session_config.yaml):
  AUTH    30 min  — authentication sessions are short
  WALLET  2 hours — wallet workflows can span time
  LOGIN  1 hour
  CONSENT 1 hour

Amplifier rules (first match wins):
  has_critical = True           → 1.25×
  high_count  >= 2              → 1.20×
  event_count >= 3 AND
    suspicious_event_count >= 2 → 1.10×
  otherwise                     → 1.00×
"""

import json
from pathlib import Path
from typing import Optional
from datetime import datetime
from core.config_loader import HotConfig
from core.logger import logger
from storage.redis_client import redis_client
from storage.db_pool import savepoint
_session_config = HotConfig(Path(__file__).parent.parent / "config/session_config.yaml")


def _get_session_ttl(action_taxonomy: Optional[str]) -> int:
    cfg = _session_config.get()
    ttls = cfg.get("session_ttl_seconds", {})
    key = (action_taxonomy or "").upper() if action_taxonomy else "default"
    return int(ttls.get(key, ttls.get("default", 3600)))


def _get_suspicious_threshold() -> int:
    cfg = _session_config.get()
    return int(cfg.get("suspicious_score_threshold", 30))


def _get_max_scores_stored() -> int:
    cfg = _session_config.get()
    return int(cfg.get("max_scores_stored", 20))


def _session_key(session_id: str) -> str:
    return f"session:state:{session_id}"


def get_session_amplifier(
    session_id: Optional[str]
) -> float:
    """
    Return the session-level score multiplier for the current event.

    Reads the session's accumulated risk state from Redis.
    Returns 1.0 (no amplification) on any failure — always fail-open.
    """
    if not session_id:
        return 1.0

    try:
        raw = redis_client.get(_session_key(session_id))
        if not raw:
            return 1.0

        state = json.loads(raw)

        if state.get("has_critical", False):
            logger.info("[SESSION] CRITICAL in session %s — amplifier=1.25", session_id)
            return 1.25

        if state.get("high_count", 0) >= 2:
            logger.info("[SESSION] 2+ HIGH in session %s — amplifier=1.20", session_id)
            return 1.20

        if (state.get("event_count", 0) >= 3
                and state.get("suspicious_event_count", 0) >= 2):
            logger.info("[SESSION] Persistent suspicion in session %s — amplifier=1.10",
                        session_id)
            return 1.10

        return 1.0

    except Exception as exc:
        logger.warning("[SESSION] get_session_amplifier failed — defaulting to 1.0: %s", exc)
        return 1.0


def update_session_state(
    session_id: Optional[str],
    score: int,
    risk_level: str,
    event_time: datetime,
    action_taxonomy: Optional[str] = None,
) -> None:
    """
    Update the session risk state in Redis after an event is scored.

    Uses the per-service TTL from session_config.yaml.
    Never raises — session update failure must not affect the scoring path.
    """
    if not session_id:
        return

    suspicious_threshold = _get_suspicious_threshold()
    max_stored = _get_max_scores_stored()
    ttl = _get_session_ttl(action_taxonomy)

    try:
        key = _session_key(session_id)
        raw = redis_client.get(key)

        if raw:
            state = json.loads(raw)
        else:
            state = {
                "event_count":            0,
                "high_count":             0,
                "has_critical":           False,
                "suspicious_event_count": 0,
                "scores":                 [],
                "service":                action_taxonomy,
                "first_event_time":       None,
                "last_event_time":        None,
            }

        state["event_count"] += 1

        event_time_iso = event_time.isoformat()
        if not state.get("first_event_time"):
            state["first_event_time"] = event_time_iso
        state["last_event_time"] = event_time_iso

        scores = state.get("scores", [])
        scores.append(score)
        state["scores"] = scores[-max_stored:]

        if risk_level == "CRITICAL":
            state["has_critical"] = True
        if risk_level in ("HIGH", "CRITICAL"):
            state["high_count"] = state.get("high_count", 0) + 1
        if score >= suspicious_threshold:
            state["suspicious_event_count"] = (
                state.get("suspicious_event_count", 0) + 1
            )

        redis_client.setex(key, ttl, json.dumps(state))

    except Exception as exc:
        logger.warning("[SESSION] update_session_state failed — continuing: %s", exc)


def persist_session_summary(db_connection, session_id: str, subject_id: str) -> None:
    """
    Write or update the durable session record in fraud_sessions.
    Best-effort — failure is logged but never re-raised.
    """
    if not session_id:
        return

    sql = """
        INSERT INTO fraud_sessions (
            session_id, subject_id, event_count, high_event_count,
            has_critical, max_score, session_risk_level,
            first_event_at, last_event_at, updated_at
        )
        SELECT
            %s, %s,
            (state->>'event_count')::int,
            (state->>'high_count')::int,
            (state->>'has_critical')::boolean,
            CASE
                WHEN jsonb_array_length(state->'scores') > 0
                THEN (SELECT MAX(s::int) FROM jsonb_array_elements_text(state->'scores') AS s)
                ELSE 0
            END,
            CASE
                WHEN (state->>'has_critical')::boolean THEN 'CRITICAL'
                WHEN (state->>'high_count')::int >= 2  THEN 'HIGH'
                WHEN jsonb_array_length(state->'scores') > 0
                    AND (SELECT MAX(s::int) FROM jsonb_array_elements_text(state->'scores') AS s) >= 30 THEN 'MEDIUM'
                WHEN (state->>'event_count')::int > 0 THEN 'LOW'
                ELSE 'NORISK'
            END,
            COALESCE((state->>'first_event_time')::timestamptz, NOW()),
            COALESCE((state->>'last_event_time')::timestamptz, NOW()),
            NOW()
        FROM (SELECT %s::jsonb AS state) s
        ON CONFLICT (session_id) DO UPDATE SET
            event_count        = EXCLUDED.event_count,
            high_event_count   = EXCLUDED.high_event_count,
            has_critical        = EXCLUDED.has_critical,
            max_score           = EXCLUDED.max_score,
            session_risk_level  = EXCLUDED.session_risk_level,
            first_event_at       = LEAST(fraud_sessions.first_event_at, EXCLUDED.first_event_at),
            last_event_at        = GREATEST(fraud_sessions.last_event_at, EXCLUDED.last_event_at),
            updated_at          = NOW()
    """
    try:
        raw = redis_client.get(_session_key(session_id))
        if not raw:
            return

        with savepoint(db_connection, "sp_session"):
            with db_connection.cursor() as cur:
                cur.execute(sql, (session_id, subject_id, raw))

    except Exception as exc:
        logger.warning("[SESSION] persist_session_summary failed: %s", exc)
