"""
Wallet velocity feature builders.

These features track wallet provisioning and sharing activity for the
wallet/credential/device combination and return values consumed by wallet
fraud rules.

Rule mapping:
    WALLET_PROVISION_VELOCITY
        -> provision_count

    WALLET_SHARE_VELOCITY
        -> share_count

    WALLET_PROVISION_SHARE_BURST
        -> combined_burst

Configuration:
    config/redis_ttl.yml is loaded through the shared HotConfig loader.

Redis state:
    Wallet provisioning and sharing counters are retained for their configured
    windows. The counters are intentionally stored separately so the feature
    can distinguish provisioning from sharing activity.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from core.config_loader import HotConfig
from core.context import Context
from core.errors import ErrorCode
from core.logger import logger
from rules.engine import is_rule_active
from storage.redis_client import redis_client
from storage.redis_utils import touch


_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"

# Redis behavioral-state retention. Values are stored in seconds.
_REDIS_TTL_CONFIG = HotConfig(_CONFIG_DIR / "redis_ttl.yml")


def _get_wallet_windows() -> tuple[int, int]:
    """Return provisioning and sharing retention windows in seconds."""
    config = _REDIS_TTL_CONFIG.get()
    wallet_config = config["wallet"]

    return (
        int(wallet_config["provision_window"]),
        int(wallet_config["share_window"]),
    )


def _build_wallet_scope(
    subject_id: str,
    wallet_id: str,
    credential_id: str,
    device_id: str,
) -> str:
    """
    Build a stable non-reversible Redis-key identifier for wallet activity.

    subject_id is included explicitly, not inferred from wallet/credential
    alone. Although a (wallet_id, credential_id) pair is expected to belong
    to a single subject in practice, that hasn't been verified against the
    provisioning system, so subject_id guards against velocity counters
    silently merging across subjects if that assumption ever doesn't hold.

    Hashing keeps raw identifiers out of Redis key names and prevents
    unusually long identifiers from creating oversized keys.
    """
    raw_scope = f"{subject_id}:{wallet_id}:{credential_id}:{device_id}"
    return hashlib.sha256(raw_scope.encode("utf-8")).hexdigest()


def build_wallet_velocity_features(
    context: Context,
    rule_overrides: dict,
) -> dict:
    """
    Build provisioning, sharing, and combined wallet-burst features.

    The current event increments only the counter corresponding to its wallet
    action. The other counter is read without mutation so the combined-burst
    feature reflects the accumulated activity of both actions.
    """
    try:
        wallet_payload = context.wallet_payload
        if not wallet_payload:
            return {
                "provision_count": 0,
                "share_count": 0,
                "combined_burst": 0,
            }

        provision_enabled = is_rule_active(
            "WALLET_PROVISION_VELOCITY",
            "WALLET",
            rule_overrides,
        )
        share_enabled = is_rule_active(
            "WALLET_SHARE_VELOCITY",
            "WALLET",
            rule_overrides,
        )
        combined_enabled = is_rule_active(
            "WALLET_PROVISION_SHARE_BURST",
            "WALLET",
            rule_overrides,
        )

        # No wallet rule is active, so no Redis state needs to be touched.
        if not (provision_enabled or share_enabled or combined_enabled):
            return {
                "provision_count": 0,
                "share_count": 0,
                "combined_burst": 0,
            }

        wallet_id = wallet_payload.wallet_id
        credential_id = wallet_payload.credential_id
        device_id = context.security_payload.device_id or "unknown"
        subject_id = context.subject_id

        scope = _build_wallet_scope(
            subject_id,
            wallet_id,
            credential_id,
            device_id,
        )

        provision_key = f"wallet:prov:{scope}"
        share_key = f"wallet:share:{scope}"

        provision_window_seconds, share_window_seconds = (
            _get_wallet_windows()
        )

        provision_count = 0
        share_count = 0

        # WALLET_PROVISION_VELOCITY
        if provision_enabled:
            if wallet_payload.wallet_action == "provision":
                provision_count = int(
                    redis_client.incr(provision_key)
                )
                touch(
                    provision_key,
                    provision_window_seconds,
                )
            else:
                provision_count = int(
                    redis_client.get(provision_key) or 0
                )

        # WALLET_SHARE_VELOCITY
        if share_enabled:
            if wallet_payload.wallet_action == "share":
                share_count = int(
                    redis_client.incr(share_key)
                )
                touch(
                    share_key,
                    share_window_seconds,
                )
            else:
                share_count = int(
                    redis_client.get(share_key) or 0
                )

        # WALLET_PROVISION_SHARE_BURST
        # This rule is derived from the two independently maintained counters.
        # It only produces a value when both source features are enabled.
        combined_burst = 0
        if combined_enabled and provision_enabled and share_enabled:
            combined_burst = min(
                provision_count,
                share_count,
            )

        return {
            "provision_count": provision_count,
            "share_count": share_count,
            "combined_burst": combined_burst,
        }

    except Exception as exc:
        logger.exception(
            "%s:WALLET_FEATURE_REDIS_FAILURE subject_id=%s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
        )
        raise RuntimeError(ErrorCode.REDIS_ERROR) from exc


def build_wallet_features(
    context: Context,
    rule_overrides: dict,
) -> dict:
    """Build all wallet-related features for the current event."""
    return build_wallet_velocity_features(
        context,
        rule_overrides,
    )