# # service/action_engine.py
# """
# Action Engine — Phase 2

# Resolves (action_taxonomy, risk_band, cross_service_flagged) → enforcement action.

# Each service × band entry in service_actions.yaml may specify:
#   default:                 action when no special condition applies
#   if_cross_service_flagged: override action when the subject already carries a
#                             cross-service fraud flag from an earlier event

# BLOCK is the floor: if_cross_service_flagged can only escalate, never soften a
# band whose default is already BLOCK.

# Fallback: if config is missing or a band is undefined, defaults to MONITOR so
# citizens are never silently passed through or silently blocked due to a config gap.
# """

# from pathlib import Path
# from typing import Optional

# from core.config_loader import HotConfig
# from core.constants import TAXONOMY_TO_SERVICE
# from core.logger import logger

# _action_config = HotConfig(
#     Path(__file__).parent.parent / "config/service_actions.yaml"
# )

# # Conservative fallback when config is unavailable
# _FALLBACK_ACTIONS: dict[str, str] = {
#     "NORISK":   "ALLOW",
#     "LOW":      "MONITOR",
#     "MEDIUM":   "FLAG",
#     "HIGH":     "STEP_UP",
#     "CRITICAL": "BLOCK",
# }

# # Enforcement action severity order — BLOCK cannot be softened
# _ACTION_ORDER = ["ALLOW", "MONITOR", "FLAG", "STEP_UP", "BLOCK"]


# def _stricter(a: str, b: str) -> str:
#     """Return whichever action is more restrictive."""
#     idx_a = _ACTION_ORDER.index(a) if a in _ACTION_ORDER else 0
#     idx_b = _ACTION_ORDER.index(b) if b in _ACTION_ORDER else 0
#     return a if idx_a >= idx_b else b


# def resolve_action(
#     action_taxonomy: str,
#     risk_band: str,
#     cross_service_flagged: bool = False,
# ) -> str:
#     """
#     Return the enforcement action for a given service, risk band, and flag context.

#     Args:
#         action_taxonomy:      login | enroll | consent | wallet
#         risk_band:            NORISK | LOW | MEDIUM | HIGH | CRITICAL
#         cross_service_flagged: True if subject carries a prior cross-service fraud flag

#     Returns:
#         ALLOW | MONITOR | FLAG | STEP_UP | BLOCK
#     """
#     service = TAXONOMY_TO_SERVICE.get(action_taxonomy, "AUTH")
#     config = _action_config.get()

#     service_config = config.get(service, {})
#     band_config = service_config.get(risk_band)

#     if not band_config:
#         action = _FALLBACK_ACTIONS.get(risk_band, "MONITOR")
#         logger.warning(
#             "[ACTION_ENGINE] No action defined for service=%s band=%s — using fallback=%s",
#             service, risk_band, action,
#         )
#         return action

#     # Support both old flat format ("action": "ALLOW") and new nested format
#     if isinstance(band_config, str):
#         default_action = band_config
#         override_action: Optional[str] = None
#     else:
#         default_action = band_config.get("default", "MONITOR")
#         override_action = band_config.get("if_cross_service_flagged")

#     if cross_service_flagged and override_action:
#         # if_cross_service_flagged can only escalate — BLOCK is the floor
#         action = _stricter(default_action, override_action)
#         logger.info(
#             "[ACTION_ENGINE] Cross-service flag applied service=%s band=%s "
#             "default=%s override=%s resolved=%s",
#             service, risk_band, default_action, override_action, action,
#         )
#         return action

#     return default_action
