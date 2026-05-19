from core.context import Context
from core.errors import ErrorCode
from core.logger import logger
from core.settings import REDIS_TTL, THRESHOLDS
from storage.redis_client import redis_client
from storage.redis_utils import touch

from datetime import time
from zoneinfo import ZoneInfo


def is_emulator_resolution(screen_resolution: str) -> bool:
    """
    Check whether the given screen resolution matches known
    emulator or automation-friendly resolutions.
    """
    emulator_resolutions = {"800x600", "1024x768", "1280x720"}
    return screen_resolution in emulator_resolutions


def build_auth01_auth03_features(context: Context) -> dict:
    """
    Builds AUTH-01 and AUTH-03 authentication failure-related features.
    """
    try:
        if not THRESHOLDS["AUTH-01"]["enabled"] and not THRESHOLDS["AUTH-03"]["enabled"]:
          return {
              "user_fail_count": 0,
              "fail_before_success": 0,
          }

        redis_key = f"fail:user:{context.subject_id}"
        #min_failures = THRESHOLDS["AUTH-01"]["min_failures"]
        min_failures_before_success = THRESHOLDS["AUTH-03"][
            "min_failures_before_success"
        ]
        sliding_window_seconds = REDIS_TTL["auth"]["fail_window"]

        existing_fail_count = int(redis_client.get(redis_key) or 0)

        features = {
            "user_fail_count": 0,
            "fail_before_success": 0,
        }

        if context.success:
            if existing_fail_count >= min_failures_before_success and context.authentication_type=="login":
                features["fail_before_success"] = existing_fail_count

            redis_client.delete(redis_key)
            return features

        updated_fail_count = redis_client.incr(redis_key)
        touch(redis_key, sliding_window_seconds)

        #if updated_fail_count >= min_failures:
        features["user_fail_count"] = updated_fail_count

        return features

    except Exception as err:
        logger.exception(
            "%s:AUTH_FEATURE_REDIS_FAILURE rule=AUTH-01/AUTH-03 subject_id=%s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
        )
        print(f"[ERROR] {ErrorCode.REDIS_ERROR}: AUTH-01/AUTH-03 Redis failure")
        raise RuntimeError(ErrorCode.REDIS_ERROR) from err


def build_auth02_ip_bruteforce_feature(context: Context) -> int:
    """
    Builds AUTH-02 feature to detect brute-force attempts from a single IP.
    """
    try:
        if not context.authentication_type == 'login':
            return 0
            
        if not THRESHOLDS["AUTH-02"]["enabled"]:
          return 0
        #minimum_distinct_subjects = THRESHOLDS["AUTH-02"]["min_subjects_per_ip"]
        source_ip = context.security_payload.src_ip
  
        if not source_ip or context.success:
            return 0
  
        redis_key = f"ip:fail:subjects:{source_ip}"
        sliding_window_seconds = REDIS_TTL["auth"]["ip_fail_window"]
  
        redis_client.sadd(redis_key, context.subject_id)
        touch(redis_key, sliding_window_seconds)
  
        distinct_subject_count = redis_client.scard(redis_key)
        return (
            distinct_subject_count
  #            if distinct_subject_count >= minimum_distinct_subjects
  #            else 0
        )

    except Exception as err:
        logger.exception(
            "%s:AUTH_FEATURE_REDIS_FAILURE rule=AUTH-02 ip=%s",
            ErrorCode.REDIS_ERROR,
            context.security_payload.src_ip,
        )
        print(f"[ERROR] {ErrorCode.REDIS_ERROR}: AUTH-02 Redis failure")
        raise RuntimeError(ErrorCode.REDIS_ERROR) from err


def build_new_device_feature(context: Context) -> int:
    """
    Builds AUTH-04 feature to detect new devices for a subject.
    """
    try:
        if not context.authentication_type == 'login':
            return 0
            
        if not THRESHOLDS["AUTH-04"]["enabled"]:
            return 0

        device_id = context.security_payload.device_id
        if not device_id:
            return 0

        redis_key = f"devices:user:{context.subject_id}"
        device_memory_seconds = REDIS_TTL["identity"]["device_memory"]

        redis_client.sadd(redis_key, device_id)
        touch(redis_key, device_memory_seconds)

        total_known_devices = redis_client.scard(redis_key)
        return max(0, total_known_devices - 1)

    except Exception as err:
        logger.exception(
            "%s:AUTH_FEATURE_REDIS_FAILURE rule=AUTH-04 subject_id=%s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
        )
        print(f"[ERROR] {ErrorCode.REDIS_ERROR}: AUTH-04 Redis failure")
        raise RuntimeError(ErrorCode.REDIS_ERROR) from err


def build_geo_mismatch_feature(context: Context) -> int:
    """
    Builds AUTH-05 feature to detect geographic changes.
    """
    try:
        if not context.authentication_type == 'login':
            return 0
            
        if not THRESHOLDS["AUTH-05"]["enabled"]:
            return 0

        current_geo_location = context.security_payload.geo_loc
        if not current_geo_location:
            return 0

        redis_key = f"geo:user:{context.subject_id}"
        geo_memory_seconds = REDIS_TTL["identity"]["geo_memory"]

        previous_geo_location = redis_client.get(redis_key)

        redis_client.set(redis_key, current_geo_location)
        touch(redis_key, geo_memory_seconds)

        if previous_geo_location and previous_geo_location != current_geo_location:
            return 1

        return 0

    except Exception as err:
        logger.exception(
            "%s:AUTH_FEATURE_REDIS_FAILURE rule=AUTH-05 subject_id=%s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
        )
        print(f"[ERROR] {ErrorCode.REDIS_ERROR}: AUTH-05 Redis failure")
        raise RuntimeError(ErrorCode.REDIS_ERROR) from err


def build_old_browser_feature(context: Context) -> int:
    """
    AUTH-06: Browser downgrade after failures
    """
    try:
        if not context.authentication_type == 'login':
            return 0
            
        if not THRESHOLDS["AUTH-06"]["enabled"]:
          return 0

        minimum_browser_drop = THRESHOLDS["AUTH-06"]["min_browser_drop"]
        min_failures = THRESHOLDS["AUTH-06"]["min_failures"]

        user_agent_string = context.security_payload.user_agent or ""
        if "Chrome/" not in user_agent_string:
            return 0

        current_browser_version = int(
            user_agent_string.split("Chrome/")[1].split(".")[0]
        )

        # Check failure pressure first
        failure_key = f"fail:user:{context.subject_id}"
        fail_count = int(redis_client.get(failure_key) or 0)
        if fail_count < min_failures:
            return 0

        redis_key = f"browser:user:{context.subject_id}"
        device_memory_seconds = REDIS_TTL["identity"]["browser_memory"]

        previous_browser_version_raw = redis_client.get(redis_key)

        # FIRST TIME: store version and exit
        if not previous_browser_version_raw:
            redis_client.set(redis_key, current_browser_version)
            touch(redis_key, device_memory_seconds)
            return 0

        previous_browser_version = int(previous_browser_version_raw)

        # DOWNGRADE DETECTION
        downgrade_detected = (
            previous_browser_version - current_browser_version
            >= minimum_browser_drop
        )

        # Always update to latest version
        redis_client.set(redis_key, current_browser_version)
        touch(redis_key, device_memory_seconds)

        return 1 if downgrade_detected else 0

    except Exception as err:
        logger.exception(
            "%s:AUTH_FEATURE_REDIS_FAILURE rule=AUTH-06 subject_id=%s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
        )
        raise RuntimeError(ErrorCode.REDIS_ERROR) from err



def build_screen_resolution_feature(context: Context) -> int:
    """
    Builds AUTH-07 feature to detect emulator-like resolutions.
    """
    try:
        if not context.authentication_type == 'login':
            return 0
            
        if not THRESHOLDS["AUTH-07"]["enabled"]:
           return 0

        screen_resolution = context.security_payload.screen_resolution
        if not screen_resolution:
            return 0

        #minimum_required_signals = THRESHOLDS["AUTH-07"]["min_emulator_signals"]
        if not is_emulator_resolution(screen_resolution):
            return 0

        redis_key = f"resolution:user:{context.subject_id}"
        device_memory_seconds = REDIS_TTL["identity"]["screen_resolution_memory"]

        redis_client.sadd(redis_key, screen_resolution)
        touch(redis_key, device_memory_seconds)

        resolution_count = redis_client.scard(redis_key)
        return resolution_count 
        #if resolution_count >= minimum_required_signals else 0

    except Exception as err:
        logger.exception(
            "%s:AUTH_FEATURE_REDIS_FAILURE rule=AUTH-07 subject_id=%s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
        )
        print(f"[ERROR] {ErrorCode.REDIS_ERROR}: AUTH-07 Redis failure")
        raise RuntimeError(ErrorCode.REDIS_ERROR) from err


def build_language_flip_feature(context: Context) -> int:
    """
    Builds AUTH-08 feature to detect language flips on success.
    """
    try:
        if not context.authentication_type == 'login':
            return 0
            
        if not THRESHOLDS["AUTH-08"]["enabled"]:
          return 0

        if not context.success:
            return 0

        current_language = context.security_payload.language
        if not current_language:
            return 0

        #minimum_language_changes = THRESHOLDS["AUTH-08"]["min_language_changes"]
        language_memory_seconds = REDIS_TTL["identity"]["language_memory"]

        language_key = f"lang:user:{context.subject_id}"
        language_change_counter_key = f"{language_key}:count"

        previous_language = redis_client.get(language_key)

        redis_client.set(language_key, current_language)
        touch(language_key, language_memory_seconds)

        if previous_language and previous_language != current_language:
            redis_client.incr(language_change_counter_key)
            touch(language_change_counter_key, language_memory_seconds)

        change_count = int(redis_client.get(language_change_counter_key) or 0)
        return change_count 
        #if change_count >= minimum_language_changes else 0

    except Exception as err:
        logger.exception(
            "%s:AUTH_FEATURE_REDIS_FAILURE rule=AUTH-08 subject_id=%s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
        )
        print(f"[ERROR] {ErrorCode.REDIS_ERROR}: AUTH-08 Redis failure")
        raise RuntimeError(ErrorCode.REDIS_ERROR) from err


#def build_odd_login_hour_feature(context: Context) -> int:
#    try:
#        if not context.authentication_type == 'login':
#            return 0
#            
#        if not THRESHOLDS["AUTH-09"]["enabled"]:
#          return 0
#
#        login_hour = context.event_time.hour + 5
#        #print(login_hour)
#        return 1 if login_hour < 6 or login_hour > 10 else 0
#
#    except Exception as err:
#        logger.exception(
#            "%s:AUTH_FEATURE_FAILURE rule=AUTH-09 subject_id=%s",
#            ErrorCode.INTERNAL_ERROR,
#            context.subject_id,
#        )
#        print(f"[ERROR] {ErrorCode.INTERNAL_ERROR}: AUTH-09 failure")
#        raise RuntimeError(ErrorCode.INTERNAL_ERROR) from err

def build_odd_login_hour_feature(context: Context) -> int:

    try:
        if context.authentication_type != 'login':
            return 0
            
        if not THRESHOLDS["AUTH-09"]["enabled"]:
            return 0

        # Convert UTC ? IST properly
        ist_time = context.event_time.astimezone(ZoneInfo("Asia/Kolkata"))

        login_time = ist_time.time()

        start = time(15, 0)  # 3:00 PM IST
        end = time(16, 0)    # 4:00 PM IST

        return 1 if start <= login_time <= end else 0

    except Exception as err:
        logger.exception(
            "%s:AUTH_FEATURE_FAILURE rule=AUTH-09 subject_id=%s",
            ErrorCode.INTERNAL_ERROR,
            context.subject_id,
        )
        raise RuntimeError(ErrorCode.INTERNAL_ERROR) from err


# not same odd login hour
# def build_time_of_day_anomaly_feature(context: Context) -> int:
#     hour = context.event_time.hour
#     key = f"login_hours:user:{context.subject_id}"

#     redis_client.sadd(key, hour)
#     touch(key, REDIS_TTL["behavior"]["time_of_day"])

#     hours_seen = redis_client.smembers(key)

#     # Need baseline (configurable)
#     if len(hours_seen) < 3:
#         return 0

#     if hour not in hours_seen:
#         return 1

#     return 0


def build_auth_features(context: Context) -> dict:
    """
    Aggregate all authentication-related features.
    """
    return {
        **build_auth01_auth03_features(context),
        "ip_failed_subject_count": build_auth02_ip_bruteforce_feature(context),
        "is_new_device": build_new_device_feature(context),
        "geo_mismatch": build_geo_mismatch_feature(context),
        "is_old_browser": build_old_browser_feature(context),
        "suspicious_resolution": build_screen_resolution_feature(context),
        "language_flip_on_success": build_language_flip_feature(context),
        "odd_login_hour": build_odd_login_hour_feature(context),
    }
