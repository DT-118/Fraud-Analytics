from core.context import Context
from core.errors import ErrorCode
from core.logger import logger
from core.settings import REDIS_TTL, THRESHOLDS
from storage.redis_client import redis_client
from storage.redis_utils import touch


def build_wallet_features(context: Context) -> dict:
    """
    Builds wallet-related fraud signals:
    - Signing velocity anomalies (WAL-01)
    - Critical wallet actions without recent re-authentication (WAL-02)
    """
    features = {
        "wallet_sign_velocity": 0,
        "missing_recent_reauth": 0,
    }

    try:
        wallet = context.wallet_payload
        if not wallet:
            return features

        subject_id = context.subject_id
        wallet_id = wallet.wallet_id

        # WAL-01
        if wallet.wallet_action == "sign":
            redis_key = f"wallet:sign:{wallet_id}"
            sign_window_seconds = REDIS_TTL["wallet"]["sign_window"]

            redis_client.incr(redis_key)
            touch(redis_key, sign_window_seconds)

            features["wallet_sign_velocity"] = int(redis_client.get(redis_key) or 0)

        # WAL-02
        if wallet.is_critical:
            reauth_timestamp_key = f"auth:reauth:last:{subject_id}"
            last_reauth_timestamp = redis_client.get(reauth_timestamp_key)

            if not last_reauth_timestamp:
                features["missing_recent_reauth"] = 1
            else:
                last_reauth_epoch = float(last_reauth_timestamp)
                seconds_since_reauth = (
                    context.event_time.timestamp() - last_reauth_epoch
                )

                max_allowed_age = THRESHOLDS["WAL-02"]["max_reauth_age_seconds"]
                if seconds_since_reauth > max_allowed_age:
                    features["missing_recent_reauth"] = 1

        return features

    except Exception as err:
        logger.exception(
            "%s:WALLET_FEATURE_FAILED subject_id=%s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
        )
        print(f"[ERROR] {ErrorCode.REDIS_ERROR} WALLET failed")
        raise RuntimeError(ErrorCode.REDIS_ERROR) from err
