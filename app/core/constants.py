"""
Canonical domain constants for the fraud analytics engine.

Keep this module limited to values that are stable across deployments.
Operational settings such as TTLs, thresholds, weights, rate limits, and
rule definitions belong in config/*.yaml.
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Service taxonomy
# ---------------------------------------------------------------------------
# Incoming action_taxonomy values map to the canonical service name used by
# rules, scoring, profiles, persistence, and configuration.
TAXONOMY_TO_SERVICE: dict[str, str] = {
    "auth": "AUTH",
    "login": "LOGIN",
    "consent": "CONSENT",
    "wallet": "WALLET",
}

SERVICE_TO_TAXONOMY: dict[str, str] = {
    service: taxonomy
    for taxonomy, service in TAXONOMY_TO_SERVICE.items()
}

VALID_TAXONOMIES = frozenset(TAXONOMY_TO_SERVICE)
VALID_SERVICES = frozenset(TAXONOMY_TO_SERVICE.values())

# Allowed sub-methods per taxonomy. A taxonomy not listed here accepts none.
VALID_SUB_METHODS: dict[str, frozenset[str]] = {
    "auth": frozenset({"pin", "wallet"}),   # put the auth team's real list here, lowercase
}

# ---------------------------------------------------------------------------
# Risk levels
# ---------------------------------------------------------------------------
# Keep this order stable. Numeric comparisons elsewhere in the engine use
# the position of a risk level to determine which level is more severe.
RISK_LEVELS = ("NORISK", "LOW", "MEDIUM", "HIGH", "CRITICAL")
RISK_LEVELS_SET = frozenset(RISK_LEVELS)


# ---------------------------------------------------------------------------
# Actor and execution context vocabulary
# ---------------------------------------------------------------------------

VALID_ACTOR_TYPES = frozenset(
    {"citizen", "resident", "visitor", "agent", "admin", "service", "system"}
)

VALID_ROLES = frozenset(
    {
        "CITIZEN",
        "RESIDENT",
        "VISITOR",
        "AGENT",
        "ADMIN",
        "SYSTEM",
    }
)

# actor_type -> canonical role vocabulary (used when `role` is missing/default).
# "service" is deliberately NOT mapped: mapping it to SYSTEM would silently
# suppress every rule (SYSTEM has __all__: 0.0) for events that never did before.
ACTOR_TYPE_TO_ROLE: dict[str, str] = {
    "citizen":  "CITIZEN",
    "resident": "RESIDENT",
    "visitor":  "VISITOR",
    "agent":    "AGENT",
    "admin":    "ADMIN",
    "system":   "SYSTEM",
}

VALID_ENVIRONMENTS = frozenset({"prod", "staging", "sandbox"})


# ---------------------------------------------------------------------------
# Application metadata
# ---------------------------------------------------------------------------
SERVICE_NAME = "fraud-detection-engine"