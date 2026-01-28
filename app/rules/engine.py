# rules/engine.py

import yaml
from core.errors import ErrorCode
from core.logger import logger


def load_rules(rules_file_path: str) -> dict:
    """
    Load fraud rule configuration from a YAML file.

    This function reads the rules.yaml file for a given fraud domain
    (auth, enroll, consent, wallet) and returns the parsed configuration
    as a dictionary.
    """
    try:
        with open(rules_file_path, "r") as file:
            rules_config = yaml.safe_load(file)

        if not rules_config or "rules" not in rules_config:
            raise ValueError("Invalid rules configuration structure")

        return rules_config

    except Exception as exc:
        print(f"[RULES][ERROR] Failed to load rules from {rules_file_path}")
        logger.exception(f"{ErrorCode.RULE_ENGINE_ERROR}: Failed to load rules file")
        raise RuntimeError(ErrorCode.RULE_ENGINE_ERROR) from exc


def evaluate_rule(
    rule_id: str,
    rule_definition: dict,
    feature_values: dict,
) -> dict | None:
    """
    Evaluate a single fraud rule against computed feature values.

    Returns:
        A dictionary containing rule_id and weight if triggered,
        otherwise None.
    """
    try:
        feature_name = rule_definition["feature"]
        feature_value = feature_values.get(feature_name)

        # Feature not present → rule not applicable
        if feature_value is None:
            return None

        for threshold_band in rule_definition["thresholds"]:
            minimum_value = threshold_band["min"]
            maximum_value = threshold_band.get("max")

            if maximum_value is not None:
                if minimum_value <= feature_value <= maximum_value:
                    return {
                        "rule_id": rule_id,
                        "weight": threshold_band["weight"],
                    }
            else:
                if feature_value >= minimum_value:
                    return {
                        "rule_id": rule_id,
                        "weight": threshold_band["weight"],
                    }

        return None

    except Exception as exc:
        print(f"[RULES][ERROR] Rule evaluation failed for {rule_id}")
        logger.exception(f"{ErrorCode.RULE_ENGINE_ERROR}: Rule evaluation failure")
        raise RuntimeError(ErrorCode.RULE_ENGINE_ERROR) from exc


def run_rules(rule_config: dict, feature_values: dict) -> list:
    """
    Execute all enabled fraud rules against the extracted feature set.

    Iterates over each rule defined in the configuration, evaluates it
    against the current feature values, and collects all triggered rules.

    Returns:
        A list of triggered rule dictionaries containing rule_id and weight.
    """
    triggered_rules: list = []

    try:
        for rule_id, rule_definition in rule_config["rules"].items():
            if not rule_definition.get("enabled", False):
                continue

            evaluation_result = evaluate_rule(
                rule_id,
                rule_definition,
                feature_values,
            )

            if evaluation_result:
                triggered_rules.append(evaluation_result)

        return triggered_rules

    except Exception as exc:
        print("[RULES][ERROR] Failed while running rule set")
        logger.exception(f"{ErrorCode.RULE_ENGINE_ERROR}: Rule execution failure")
        raise RuntimeError(ErrorCode.RULE_ENGINE_ERROR) from exc
