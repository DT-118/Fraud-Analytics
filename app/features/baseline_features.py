"""
baseline_features.py

Computes behavioral deviation features from a user's personal baseline (Phase 5).

For each numeric feature with a mature baseline (≥ MIN_SAMPLES observations),
computes a z-score:
    z = (observed - mean) / std_dev

Emits three derived features into the feature map:
  - {feature_name}_zscore   individual z-score per tracked feature
  - max_zscore              highest absolute z-score across all tracked features
  - deviation_score         0–100 normalized score: min(abs(max_z) / SCALE × 100, 100)
                            SCALE = 4.0 → z=4 maps to deviation_score=100

BASELINE-01 rule (in each taxonomy YAML) thresholds on deviation_score.
The rule only fires when multiple features deviate simultaneously — by design,
individual z-score features can also be targeted by future per-feature rules.

False-positive safety:
  - Requires MIN_SAMPLES=10 observations before any z-score is emitted,
    so new users are never penalized.
  - deviation_score is suppressed to 0 for z-scores below the service's
    configured tolerance_sigma, reducing noise from minor fluctuations.
"""

from core.logger import logger

_MIN_SAMPLES: int    = 10   # observations required before baseline is trusted
_ZSCORE_SCALE: float = 4.0  # z=4 → deviation_score=100


def build_baseline_features(
    feature_values: dict,
    baselines: dict[str, dict],
    tolerance_config: dict[str, float] | None = None,
) -> dict:
    """
    Compute z-score deviation features from a user's personal feature baselines.

    Args:
        feature_values:   Current event's computed feature dict.
        baselines:        Output of fetch_baselines() — {feature_name: {mean, std_dev, sample_count}}.
        tolerance_config: Output of fetch_service_tolerance() — {feature_name: sigma_threshold}.
                          '*' is the catch-all default key.  z-scores below threshold are suppressed.

    Returns:
        Deviation feature dict to merge into feature_values.
        Always returns at least {"max_zscore": 0.0, "deviation_score": 0.0}
        so BASELINE-01 has a defined feature value on every event.
    """
    if tolerance_config is None:
        tolerance_config = {}

    default_tolerance = tolerance_config.get("*", 0.0)

    zscore_features: dict = {}
    abs_zscores: list[float] = []

    for feature_name, baseline in baselines.items():
        if baseline["sample_count"] < _MIN_SAMPLES:
            continue
        if baseline["std_dev"] < 0.001:
            continue

        observed = feature_values.get(feature_name)
        if observed is None or not isinstance(observed, (int, float)):
            continue

        z = (float(observed) - baseline["mean"]) / baseline["std_dev"]
        tolerance = tolerance_config.get(feature_name, default_tolerance)

        if abs(z) < tolerance:
            continue

        zscore_features[f"{feature_name}_zscore"] = round(z, 4)
        abs_zscores.append(abs(z))

    if abs_zscores:
        max_z = max(abs_zscores)
        deviation_score = min(100.0, round(max_z / _ZSCORE_SCALE * 100.0, 2))
    else:
        max_z = 0.0
        deviation_score = 0.0

    return {
        **zscore_features,
        "max_zscore":      round(max_z, 4),
        "deviation_score": deviation_score,
    }
