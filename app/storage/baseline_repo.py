"""
baseline_repo.py

Persistence layer for per-user per-feature behavioral baselines (Phase 5).

Each (subject_id, service, feature_name) triple accumulates a rolling mean
and variance using Welford's online algorithm, which allows incremental updates
without storing all historical values.

Welford update after observing value x:
    n_new  = n + 1
    delta  = x - old_mean
    mean   = old_mean + delta / n_new
    delta2 = x - new_mean
    M2     = old_M2 + delta * delta2
    std_dev = sqrt(M2 / (n-1))   for n >= 2

The upsert is performed atomically in a single SQL expression to avoid
the SELECT → compute → INSERT race condition under concurrent updates.
"""

import math
from typing import Optional

from core.errors import ErrorCode
from core.logger import logger

# Features that are DERIVED from baselines — never feed them back into baselines
# to avoid circular z-score amplification.
_DERIVED_FEATURE_SUFFIXES = ("_zscore",)
_DERIVED_FEATURE_NAMES    = {"max_zscore", "deviation_score"}


def _is_derived_feature(name: str) -> bool:
    if name in _DERIVED_FEATURE_NAMES:
        return True
    return any(name.endswith(s) for s in _DERIVED_FEATURE_SUFFIXES)


def fetch_baselines(
    db_connection,
    subject_id: str,
    service: str,
) -> dict[str, dict]:
    """
    Return all mature baselines for a (subject_id, service) pair.

    Returns:
        {feature_name: {"mean": float, "std_dev": float, "sample_count": int}}
        Empty dict on DB failure — fail-open so scoring is never blocked.
    """
    sql = """
        SELECT feature_name, mean, m2, sample_count
        FROM   user_feature_baseline
        WHERE  subject_id = %s AND service = %s
    """
    try:
        with db_connection.cursor() as cur:
            cur.execute(sql, (subject_id, service))
            rows = cur.fetchall()

        result: dict[str, dict] = {}
        for feature_name, mean, m2, sample_count in rows:
            std_dev = math.sqrt(float(m2) / (sample_count - 1)) if sample_count >= 2 else 0.0
            result[feature_name] = {
                "mean":         float(mean),
                "std_dev":      std_dev,
                "sample_count": sample_count,
            }
        return result

    except Exception as exc:
        logger.warning(
            "[BASELINE] fetch_baselines failed subject_id=%s service=%s: %s",
            subject_id, service, exc,
        )
        return {}


def fetch_service_tolerance(
    db_connection,
    service: str,
) -> dict[str, float]:
    """
    Return the deviation tolerance config for this service.

    Keys are feature_name ('*' is the catch-all default).
    Falls back to {"*": 2.5} on DB failure.
    """
    sql = """
        SELECT feature_name, tolerance_sigma
        FROM   service_deviation_config
        WHERE  service = %s AND enabled = TRUE
    """
    try:
        with db_connection.cursor() as cur:
            cur.execute(sql, (service,))
            rows = cur.fetchall()
        return {row[0]: float(row[1]) for row in rows} if rows else {"*": 2.5}

    except Exception as exc:
        logger.warning("[BASELINE] fetch_service_tolerance failed service=%s: %s", service, exc)
        return {"*": 2.5}


def upsert_baseline(
    db_connection,
    subject_id: str,
    service: str,
    feature_name: str,
    new_value: float,
) -> None:
    """
    Apply one atomic Welford update to a single feature baseline.

    The entire SELECT + compute + INSERT is expressed as a single SQL
    statement so there is no race between reading old values and writing
    new ones.  Safe to call from a background thread.
    """
    sql = """
        INSERT INTO user_feature_baseline
            (subject_id, service, feature_name, mean, m2, sample_count, updated_at)
        VALUES (%s, %s, %s, %s, 0.0, 1, NOW())
        ON CONFLICT (subject_id, service, feature_name) DO UPDATE SET
            sample_count = user_feature_baseline.sample_count + 1,
            mean = user_feature_baseline.mean
                   + (%s - user_feature_baseline.mean)
                   / (user_feature_baseline.sample_count + 1),
            m2   = user_feature_baseline.m2
                   + (%s - user_feature_baseline.mean)
                   * (%s - (
                         user_feature_baseline.mean
                         + (%s - user_feature_baseline.mean)
                         / (user_feature_baseline.sample_count + 1)
                      )),
            updated_at = NOW()
    """
    try:
        with db_connection.cursor() as cur:
            cur.execute(sql, (
                subject_id, service, feature_name, new_value,  # INSERT values
                new_value,   # delta = x - old_mean   (first %s in mean expr)
                new_value,   # delta term 1 in m2 expr (x - old_mean)
                new_value,   # delta2 term in m2 expr  (x - new_mean, numerator)
                new_value,   # delta inside new_mean subexpression
            ))

    except Exception as exc:
        logger.warning(
            "[BASELINE] upsert_baseline failed %s/%s/%s: %s",
            subject_id, service, feature_name, exc,
        )


def upsert_baselines_for_event(
    db_connection,
    subject_id: str,
    service: str,
    feature_values: dict,
) -> None:
    """
    Update baselines for all raw numeric features in a scored event.

    Derived features (z-scores, deviation_score, max_zscore) are explicitly
    excluded to prevent circular amplification.  Called from a background thread.
    """
    for feature_name, value in feature_values.items():
        if _is_derived_feature(feature_name):
            continue
        if not isinstance(value, (int, float)):
            continue
        try:
            upsert_baseline(db_connection, subject_id, service, feature_name, float(value))
        except Exception:
            pass
