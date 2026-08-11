"""
profile_repo.py

Persistence layer for dynamic risk profiles (Phase 3).

Two tables:
  user_service_risk_profile   — one row per (subject_id, service)
  user_identity_risk_profile  — one row per subject_id (composite)

Time-decay (EWMA) formula applied on upsert:
  α  = e^{-λ × Δt_days}   where λ = 0.1  (half-life ≈ 7 days)
  new_rolling = old_rolling × α  +  new_score × (1 − α)

If there is no prior row, the incoming score becomes the initial rolling score.
"""

import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from core.config_loader import HotConfig
from core.errors import ErrorCode
from core.logger import logger

# Decay constant — ln(2)/7 ≈ 0.099; using 0.1 gives a ~7-day half-life
_DECAY_LAMBDA: float = 0.1

_weights_config = HotConfig(Path(__file__).parent.parent / "config/service_weights.yaml")

_RISK_ORDER = ["NORISK", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _get_service_weights() -> tuple[dict[str, float], float]:
    cfg = _weights_config.get()
    weights = cfg.get("composite_weights", {
        "AUTH": 0.40, "ENROLL": 0.25, "WALLET": 0.25, "CONSENT": 0.10,
    })
    bonus = float(cfg.get("cross_service_bonus", 15))
    return weights, bonus


def _decay_factor(last_event_time: Optional[datetime]) -> float:
    """Return EWMA decay factor α = e^{-λ × Δt_days}.  Returns 0.0 if no prior event."""
    if last_event_time is None:
        return 0.0  # no prior score — new_score weighted fully
    now = datetime.now(timezone.utc)
    if last_event_time.tzinfo is None:
        last_event_time = last_event_time.replace(tzinfo=timezone.utc)
    delta_days = (now - last_event_time).total_seconds() / 86400.0
    return math.exp(-_DECAY_LAMBDA * delta_days)


def _higher_risk(a: str, b: str) -> str:
    """Return whichever risk level is higher between a and b."""
    idx_a = _RISK_ORDER.index(a) if a in _RISK_ORDER else 0
    idx_b = _RISK_ORDER.index(b) if b in _RISK_ORDER else 0
    return a if idx_a >= idx_b else b


def upsert_service_profile(
    db_connection,
    subject_id: str,
    service: str,
    new_score: int,
    event_id: str,
    event_time: datetime,
    risk_level: str,
    #action_taken: str,
) -> float:
    """
    Upsert the per-service rolling risk score with time-decay.

    Returns the new rolling_score so the caller can propagate it to the
    composite identity profile without an extra SELECT.
    """
    fetch_sql = """
        SELECT rolling_score, last_event_time, event_count
        FROM   user_service_risk_profile
        WHERE  subject_id = %s AND service = %s
    """
    upsert_sql = """
        INSERT INTO user_service_risk_profile (
            subject_id, service, rolling_score, event_count,
            last_event_id, last_event_time, last_risk_level,
            last_action_taken, updated_at
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
        ON CONFLICT (subject_id, service) DO UPDATE SET
            rolling_score     = EXCLUDED.rolling_score,
            event_count       = EXCLUDED.event_count,
            last_event_id     = EXCLUDED.last_event_id,
            last_event_time   = EXCLUDED.last_event_time,
            last_risk_level   = EXCLUDED.last_risk_level,
            last_action_taken = EXCLUDED.last_action_taken,
            updated_at        = NOW()
    """
    try:
        with db_connection.cursor() as cur:
            cur.execute(fetch_sql, (subject_id, service))
            row = cur.fetchone()

        if row:
            old_rolling, last_event_time, event_count = row
            alpha = _decay_factor(last_event_time)
            new_rolling = round(float(old_rolling) * alpha + new_score * (1.0 - alpha), 2)
            new_count = event_count + 1
        else:
            new_rolling = float(new_score)
            new_count = 1

        new_rolling = min(100.0, max(0.0, new_rolling))

        with db_connection.cursor() as cur:
            cur.execute(upsert_sql, (
                subject_id, service, new_rolling, new_count,
                event_id, event_time, risk_level, None, #action_taken,
            ))

        return new_rolling

    except Exception as exc:
        logger.exception("%s: upsert_service_profile failed subject_id=%s service=%s",
                         ErrorCode.DB_ERROR, subject_id, service)
        raise RuntimeError(ErrorCode.DB_ERROR) from exc


def upsert_identity_profile(
    db_connection,
    subject_id: str,
    service_scores: dict[str, float],
    cross_service_flag: bool = False,
    cross_service_flag_reason: Optional[str] = None,
) -> float:
    """
    Recompute and persist the composite identity risk profile.

    composite = Σ (weight_i × score_i)  +  cross_service_bonus (15 pts if flagged)

    highest_risk_level tracks the historical maximum — it only ever increases.
    Returns the new composite_score.
    """
    service_weights, cross_service_bonus = _get_service_weights()
    weighted = sum(
        service_weights.get(svc, 0.0) * score
        for svc, score in service_scores.items()
    )
    cross_bonus = cross_service_bonus if cross_service_flag else 0.0
    composite = min(100.0, round(weighted + cross_bonus, 2))

    # Derive the current event's risk band from composite score
    if composite >= 80:
        current_band = "CRITICAL"
    elif composite >= 60:
        current_band = "HIGH"
    elif composite >= 30:
        current_band = "MEDIUM"
    elif composite > 0:
        current_band = "LOW"
    else:
        current_band = "NORISK"

    upsert_sql = """
        INSERT INTO user_identity_risk_profile (
            subject_id, composite_score,
            auth_score, enroll_score, consent_score, wallet_score,
            cross_service_flag, cross_service_flag_reason, cross_service_flag_at,
            total_events, highest_risk_level, updated_at
        )
        VALUES (
            %s, %s,
            %s, %s, %s, %s,
            %s, %s,
            CASE WHEN %s THEN NOW() ELSE NULL END,
            1,
            %s,
            NOW()
        )
        ON CONFLICT (subject_id) DO UPDATE SET
            composite_score           = EXCLUDED.composite_score,
            auth_score                = EXCLUDED.auth_score,
            enroll_score              = EXCLUDED.enroll_score,
            consent_score             = EXCLUDED.consent_score,
            wallet_score              = EXCLUDED.wallet_score,
            -- Once flagged, flag is never cleared by a normal (non-flagged) event.
            cross_service_flag        = EXCLUDED.cross_service_flag
                                        OR user_identity_risk_profile.cross_service_flag,
            cross_service_flag_reason = CASE
                                            WHEN EXCLUDED.cross_service_flag
                                            THEN EXCLUDED.cross_service_flag_reason
                                            ELSE user_identity_risk_profile.cross_service_flag_reason
                                        END,
            cross_service_flag_at     = CASE
                                            WHEN EXCLUDED.cross_service_flag
                                                 AND user_identity_risk_profile.cross_service_flag_at IS NULL
                                            THEN NOW()
                                            ELSE user_identity_risk_profile.cross_service_flag_at
                                        END,
            total_events              = user_identity_risk_profile.total_events + 1,
            -- Historical maximum: only advance to a higher band, never go lower
            highest_risk_level        = CASE
                WHEN EXCLUDED.highest_risk_level = 'CRITICAL' THEN 'CRITICAL'
                WHEN EXCLUDED.highest_risk_level = 'HIGH'
                     AND user_identity_risk_profile.highest_risk_level <> 'CRITICAL'
                     THEN 'HIGH'
                WHEN EXCLUDED.highest_risk_level = 'MEDIUM'
                     AND user_identity_risk_profile.highest_risk_level NOT IN ('CRITICAL', 'HIGH')
                     THEN 'MEDIUM'
                WHEN EXCLUDED.highest_risk_level = 'LOW'
                     AND user_identity_risk_profile.highest_risk_level = 'NORISK'
                     THEN 'LOW'
                ELSE user_identity_risk_profile.highest_risk_level
            END,
            updated_at                = NOW()
    """
    try:
        auth_s    = service_scores.get("AUTH", 0.0)
        enroll_s  = service_scores.get("ENROLL", 0.0)
        consent_s = service_scores.get("CONSENT", 0.0)
        wallet_s  = service_scores.get("WALLET", 0.0)

        with db_connection.cursor() as cur:
            cur.execute(upsert_sql, (
                subject_id, composite,
                auth_s, enroll_s, consent_s, wallet_s,
                cross_service_flag, cross_service_flag_reason,
                cross_service_flag,   # CASE for cross_service_flag_at on INSERT
                current_band,         # highest_risk_level on INSERT
            ))

        return composite

    except Exception as exc:
        logger.exception("%s: upsert_identity_profile failed subject_id=%s",
                         ErrorCode.DB_ERROR, subject_id)
        raise RuntimeError(ErrorCode.DB_ERROR) from exc


def fetch_cross_service_flag(db_connection, subject_id: str) -> bool:
    """
    Return the current cross_service_flag for a subject, or False if no profile exists.
    Lightweight single-column SELECT used before action resolution.
    """
    sql = """
        SELECT cross_service_flag
        FROM   user_identity_risk_profile
        WHERE  subject_id = %s
    """
    try:
        with db_connection.cursor() as cur:
            cur.execute(sql, (subject_id,))
            row = cur.fetchone()
        return bool(row[0]) if row else False
    except Exception as exc:
        logger.warning("[PROFILE] fetch_cross_service_flag failed subject_id=%s: %s",
                       subject_id, exc)
        return False


def fetch_service_profiles(db_connection, subject_id: str) -> list[dict]:
    """Return all per-service profile rows for a given subject_id."""
    sql = """
        SELECT service, rolling_score, event_count,
               last_event_id, last_event_time,
               last_risk_level, last_action_taken, updated_at
        FROM   user_service_risk_profile
        WHERE  subject_id = %s
        ORDER BY service
    """
    try:
        with db_connection.cursor() as cur:
            cur.execute(sql, (subject_id,))
            rows = cur.fetchall()

        return [
            {
                "service":           r[0],
                "rolling_score":     float(r[1]),
                "event_count":       r[2],
                "last_event_id":     str(r[3]) if r[3] else None,
                "last_event_time":   r[4].isoformat() if r[4] else None,
                "last_risk_level":   r[5],
                "last_action_taken": r[6],
                "updated_at":        r[7].isoformat() if r[7] else None,
            }
            for r in rows
        ]
    except Exception as exc:
        logger.exception("%s: fetch_service_profiles failed subject_id=%s",
                         ErrorCode.DB_ERROR, subject_id)
        raise RuntimeError(ErrorCode.DB_ERROR) from exc


def fetch_identity_profile(db_connection, subject_id: str) -> Optional[dict]:
    """Return the composite identity profile row, or None if not yet built."""
    sql = """
        SELECT composite_score, auth_score, enroll_score, consent_score, wallet_score,
               cross_service_flag, cross_service_flag_reason, cross_service_flag_at,
               total_events, highest_risk_level, updated_at
        FROM   user_identity_risk_profile
        WHERE  subject_id = %s
    """
    try:
        with db_connection.cursor() as cur:
            cur.execute(sql, (subject_id,))
            row = cur.fetchone()

        if not row:
            return None

        return {
            "composite_score":            float(row[0]),
            "service_scores": {
                "AUTH":    float(row[1]),
                "ENROLL":  float(row[2]),
                "CONSENT": float(row[3]),
                "WALLET":  float(row[4]),
            },
            "cross_service_flag":          row[5],
            "cross_service_flag_reason":   row[6],
            "cross_service_flag_at":       row[7].isoformat() if row[7] else None,
            "total_events":                row[8],
            "highest_risk_level":          row[9],
            "updated_at":                  row[10].isoformat() if row[10] else None,
        }
    except Exception as exc:
        logger.exception("%s: fetch_identity_profile failed subject_id=%s",
                         ErrorCode.DB_ERROR, subject_id)
        raise RuntimeError(ErrorCode.DB_ERROR) from exc



def fetch_service_subject_profiles(
    db_connection, service: str, page: int = 1, limit: int = 50
) -> dict:
    """
    Return every subject_id's risk profile row for a given service.

    Used for the service-wide roster view (all users under AUTH/ENROLL/
    CONSENT/WALLET), as opposed to fetch_service_profiles which is
    per-subject across all services.
    """
    offset = (page - 1) * limit

    count_sql = """
        SELECT COUNT(*) FROM user_service_risk_profile WHERE service = %s
    """
    avg_sql = """
        SELECT AVG(rolling_score) FROM user_service_risk_profile WHERE service = %s
    """
    risk_breakdown_sql = """
        SELECT last_risk_level, COUNT(*)
        FROM user_service_risk_profile
        WHERE service = %s
        GROUP BY last_risk_level
    """
    action_breakdown_sql = """
        SELECT last_action_taken, COUNT(*)
        FROM user_service_risk_profile
        WHERE service = %s
        GROUP BY last_action_taken
    """
    data_sql = """
        SELECT subject_id, rolling_score, event_count,
               last_event_id, last_event_time,
               last_risk_level, last_action_taken, updated_at
        FROM user_service_risk_profile
        WHERE service = %s
        ORDER BY rolling_score DESC
        LIMIT %s OFFSET %s
    """

    try:
        with db_connection.cursor() as cur:
            cur.execute(count_sql, (service,))
            total = cur.fetchone()[0]

            cur.execute(avg_sql, (service,))
            avg_rolling = cur.fetchone()[0]

            cur.execute(risk_breakdown_sql, (service,))
            risk_level_breakdown = {r[0]: r[1] for r in cur.fetchall()}

            cur.execute(action_breakdown_sql, (service,))
            action_breakdown = {r[0]: r[1] for r in cur.fetchall()}

            cur.execute(data_sql, (service, limit, offset))
            rows = cur.fetchall()

        data = [
            {
                "subject_id":        r[0],
                "rolling_score":     float(r[1]),
                "event_count":       r[2],
                "last_event_id":     str(r[3]) if r[3] else None,
                "last_event_time":   r[4].isoformat() if r[4] else None,
                "last_risk_level":   r[5],
                "last_action_taken": r[6],
                "updated_at":        r[7].isoformat() if r[7] else None,
            }
            for r in rows
        ]

        return {
            "service": service,
            "summary": {
                "total_subjects":       int(total or 0),
                "avg_rolling_score":    round(float(avg_rolling or 0), 2),
                "risk_level_breakdown": risk_level_breakdown,
                "action_breakdown":     action_breakdown,
            },
            "data":        data,
            "page":        page,
            "limit":       limit,
            "total":       int(total or 0),
            "total_pages": (int(total or 0) + limit - 1) // limit,
        }

    except Exception as exc:
        logger.exception("%s: fetch_service_subject_profiles failed service=%s",
                         ErrorCode.DB_ERROR, service)
        raise RuntimeError(ErrorCode.DB_ERROR) from exc