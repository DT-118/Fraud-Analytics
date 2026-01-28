# scoring/engine.py
import yaml
from core.errors import ErrorCode
from core.logger import logger


def load_scores(scores_file_path: str) -> dict:
    """
    Load scoring configuration from a YAML file.

    The scoring configuration defines risk bands that map
    aggregated fraud scores to human-readable risk levels
    (LOW, MEDIUM, HIGH, CRITICAL).
    """
    try:
        with open(scores_file_path) as file:
            score_config = yaml.safe_load(file)

        if not score_config or "risk_bands" not in score_config:
            raise ValueError("Invalid scoring configuration structure")

        return score_config

    except Exception as exc:
        print(f"[SCORING][ERROR] Failed to load scores from {scores_file_path}")
        logger.exception(f"{ErrorCode.INTERNAL_ERROR}: Failed to load scoring config")
        raise RuntimeError(ErrorCode.INTERNAL_ERROR) from exc


def aggregate_score(triggered_rules: list) -> int:
    """
    Aggregate the total fraud score from triggered rules.

    Each triggered rule contributes a weight, and the final
    score is the sum of all rule weights.
    """
    try:
        return sum(rule["weight"] for rule in triggered_rules)

    except Exception as exc:
        print("[SCORING][ERROR] Failed to aggregate score")
        logger.exception(f"{ErrorCode.INTERNAL_ERROR}: Score aggregation failed")
        raise RuntimeError(ErrorCode.INTERNAL_ERROR) from exc


def classify_risk(total_score: int, score_cfg: dict) -> str:
    """
    Classify a numerical fraud score into a risk level.

    Iterates through configured risk bands and returns the
    corresponding risk level for the given score.
    """
    try:
        risk_bands = score_cfg["risk_bands"]

        for risk_level, (lower_bound, upper_bound) in risk_bands.items():
            if lower_bound <= total_score <= upper_bound:
                return risk_level

        # Defensive fallback
        return "UNKNOWN"

    except Exception as exc:
        print("[SCORING][ERROR] Risk classification failed")
        logger.exception(f"{ErrorCode.INTERNAL_ERROR}: Risk classification failure")
        raise RuntimeError(ErrorCode.INTERNAL_ERROR) from exc
