"""
liveness_suggestion.py

Post-scoring advisory for every service (AUTH, LOGIN, CONSENT, WALLET).
Doesn't affect the score itself — runs after scoring and recommends whether
to step up to Active Liveness.

Called from fraud_service.handle_fraud_event() and attached to the decision
as "active_liveness_suggestion".
"""

from typing import Optional


def get_active_liveness_suggestion(
    risk_level: str,
    identity_profile: Optional[dict],
) -> dict:
    """
    Determine whether Active Liveness should be suggested for an event.

    Active Liveness is suggested when:
      - current event risk is CRITICAL, or
      - user's historical highest risk is CRITICAL.
    """
    active_liveness_suggested = False
    active_liveness_reason = None

    # No profile yet (first-ever event for this subject) -> treat as NORISK.
    historical_highest_risk = (
        identity_profile.get("highest_risk_level")
        if identity_profile
        else "NORISK"
    )

    # Current event wins over history if both are CRITICAL.
    if risk_level == "CRITICAL":
        active_liveness_suggested = True
        active_liveness_reason = "CURRENT_EVENT_CRITICAL"

    # highest_risk_level is monotonic (never decays) — flags a
    # previously-compromised identity even on a clean current authentication.
    elif historical_highest_risk == "CRITICAL":
        active_liveness_suggested = True
        active_liveness_reason = "HISTORICAL_CRITICAL_PROFILE"

    return {
        "active_liveness_suggested": active_liveness_suggested,
        "reason": active_liveness_reason,
    }