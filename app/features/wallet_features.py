from core.context import Context
from core.errors import ErrorCode
from core.logger import logger
from core.settings import REDIS_TTL, THRESHOLDS
from storage.redis_client import redis_client
from storage.redis_utils import touch


def build_wallet_velocity_features(context: Context) -> dict:
    """
    Builds wallet provisioning and sharing velocity features.
    Also computes combined burst using min(provision, share).
    Feature updates respect THRESHOLDS enabled flags.
    """
    try:
        user_id = context.subject_id

        provision_key = f"wallet:prov:user:{user_id}"
        share_key = f"wallet:share:user:{user_id}"

        provision_window_seconds = REDIS_TTL["wallet"]["provision_window"]
        share_window_seconds = REDIS_TTL["wallet"]["share_window"]

        provision_enabled = THRESHOLDS.get("WAL-01", {}).get("enabled", True)
        share_enabled = THRESHOLDS.get("WAL-02", {}).get("enabled", True)
        combined_enabled = THRESHOLDS.get("WAL-03", {}).get("enabled", True)

        # Default values
        provision_count = 0
        share_count = 0
        combined_burst = 0

        wallet_payload = context.wallet_payload
        if not wallet_payload:
            return {"provision_count": 0, "share_count": 0, "combined_burst": 0}

        # Provision velocity
        if provision_enabled:
            if wallet_payload.wallet_action == "provision":
                provision_count = redis_client.incr(provision_key)
                touch(provision_key, provision_window_seconds)
            else:
                provision_count = int(redis_client.get(provision_key) or 0)

        # Share velocity
        if share_enabled:
            if wallet_payload.wallet_action == "share":
                share_count = redis_client.incr(share_key)
                touch(share_key, share_window_seconds)
            else:
                share_count = int(redis_client.get(share_key) or 0)

        # Combined burst
        if combined_enabled and provision_enabled and share_enabled:
            combined_burst = min(provision_count, share_count)

        return {
            "provision_count": provision_count,
            "share_count": share_count,
            "combined_burst": combined_burst,
        }

    except Exception as err:
        logger.exception(
            "%s:WALLET_FEATURE_REDIS_FAILURE subject_id=%s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
        )
        raise RuntimeError(ErrorCode.REDIS_ERROR) from err


def build_wallet_features(context: Context) -> dict:
    """
    Aggregate all wallet-related features.
    """
    return {
        **build_wallet_velocity_features(context),
    }
