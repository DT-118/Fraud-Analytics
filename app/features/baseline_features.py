"""
baseline_features.py

Computes behavioral deviation features from a user's personal baseline.

For each numeric feature with a mature baseline (≥ MIN_SAMPLES observations),
computes a z-score:
    z = (observed - mean) / std_dev

Emits three derived features into the feature map:
  - {feature_name}_zscore   individual z-score per tracked feature
  - max_zscore              highest absolute z-score across all tracked features
  - deviation_score         0–100 whole number: min(abs(max_z) / SCALE × 100, 100),
                            rounded half-up (same as classify_score_band) so integer
                            threshold bands have no gaps

BASELINE_BEHAVIOR_ANOMALY rule (in each taxonomy YAML) thresholds on deviation_score.
The rule only fires when multiple features deviate simultaneously — by design,
individual z-score features can also be targeted by future per-feature rules.

False-positive safety:
  - Requires MIN_SAMPLES=10 observations before any z-score is emitted,
    so new users are never penalized.
  - deviation_score is suppressed to 0 for z-scores below the service's
    configured tolerance_sigma, reducing noise from minor fluctuations.
"""

from __future__ import annotations
import math 
import os


def _get_positive_int_env(name: str, default: int) -> int:
    """Read a positive integer environment setting or raise a clear startup error."""
    raw_value = os.getenv(name, str(default))

    try:
        value = int(raw_value)
    except ValueError as exc:
        raise RuntimeError(
            f"{name} must be a positive integer; got {raw_value!r}"
        ) from exc

    if value <= 0:
        raise RuntimeError(
            f"{name} must be greater than zero; got {value}"
        )

    return value


def _get_positive_float_env(name: str, default: float) -> float:
    """Read a positive floating-point environment setting or raise a clear error."""
    raw_value = os.getenv(name, str(default))

    try:
        value = float(raw_value)
    except ValueError as exc:
        raise RuntimeError(
            f"{name} must be a positive number; got {raw_value!r}"
        ) from exc

    if value <= 0:
        raise RuntimeError(
            f"{name} must be greater than zero; got {value}"
        )

    return value


# Baseline calculation parameters are deployment-level settings rather than
# rule thresholds, so they remain environment-configurable.
_MIN_SAMPLES = _get_positive_int_env("BASELINE_MIN_SAMPLES", 10)
_ZSCORE_SCALE = _get_positive_float_env("BASELINE_ZSCORE_SCALE", 4.0)


# BASELINE_BEHAVIOR_ANOMALY
def build_baseline_features(
    feature_values: dict,
    baselines: dict[str, dict],
    tolerance_config: dict[str, float] | None = None,
) -> dict:
    """
    Compute z-score deviation features from personal feature baselines.

    Args:
        feature_values:
            Current event's calculated feature values.
        baselines:
            Mapping of feature name to mean, standard deviation, and sample
            count, normally returned by the baseline repository.
        tolerance_config:
            Per-feature sigma thresholds. ``*`` provides the default.

    Returns:
        A feature dictionary containing individual z-scores, ``max_zscore``,
        and ``deviation_score``. The latter two are always present.
    """
    tolerance_config = tolerance_config or {}
    default_tolerance = float(tolerance_config.get("*", 0.0))

    zscore_features: dict[str, float] = {}
    absolute_zscores: list[float] = []

    for feature_name, baseline in baselines.items():
        sample_count = baseline.get("sample_count", 0)
        standard_deviation = baseline.get("std_dev", 0.0)

        if sample_count < _MIN_SAMPLES:
            continue

        if standard_deviation < 0.001:
            continue

        observed = feature_values.get(feature_name)
        if observed is None or isinstance(observed, bool):
            continue

        if not isinstance(observed, (int, float)):
            continue

        z_score = (
            float(observed) - float(baseline["mean"])
        ) / float(standard_deviation)

        tolerance = float(
            tolerance_config.get(feature_name, default_tolerance)
        )

        if abs(z_score) < tolerance:
            continue

        zscore_features[f"{feature_name}_zscore"] = round(z_score, 4)
        absolute_zscores.append(abs(z_score))

    if absolute_zscores:
        max_zscore = max(absolute_zscores)
        deviation_score = float(
            min(100, math.floor((max_zscore / _ZSCORE_SCALE) * 100.0 + 0.5))
        )
    else:
        max_zscore = 0.0
        deviation_score = 0.0

    return {
        **zscore_features,
        "max_zscore": round(max_zscore, 4),
        "deviation_score": deviation_score,
    }