"""
profile_updater.py

BACKFILL / REPLAY consumer for the fraud.scored.events topic.

--- Role ---
Live profile updates are handled directly inside fraud_service.py via a
daemon thread (_update_profile_async). That path covers both HTTP and Kafka
ingestion automatically, with no dependency on this process being alive.

This consumer exists for two operational scenarios only:

  1. BACKFILL — profiles were lost or corrupted. Replay historical events
     from fraud.scored.events (Kafka retains messages by configured retention)
     to reconstruct user_service_risk_profile and user_identity_risk_profile
     from scratch without rerunning the live scoring engine.

  2. NEW ENVIRONMENT — standing up a new deployment that needs to seed profiles
     from an existing event history before going live.

Do NOT run this process continuously alongside the live scoring engine unless
you specifically need a backfill. Running it continuously would apply each
scored event's profile update TWICE (once from fraud_service.py's daemon thread,
once from here), causing double-weighted EWMA accumulation.

Required env vars:
  KAFKA_BOOTSTRAP_SERVERS   e.g. broker1:9092,broker2:9092
  KAFKA_PROFILE_GROUP_ID    e.g. fraud-profile-backfill (optional, has default)
"""

from dotenv import load_dotenv

load_dotenv()

import json
import os
from datetime import datetime, timezone

from confluent_kafka import Consumer
from core.errors import ErrorCode
from core.logger import logger
from service.profile_service import update_risk_profile
from storage.db import get_db_connection, release_db_connection

_SCORED_EVENTS_TOPIC = "fraud.scored.events"
_PROFILE_DLQ_TOPIC   = "fraud.scored.events.DLQ"

_KAFKA_CONFIG = {
    "bootstrap.servers": os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
    "group.id":          os.environ.get("KAFKA_PROFILE_GROUP_ID", "fraud-profile-updater-1"),
    "auto.offset.reset": "earliest",
    "enable.auto.commit": False,
}


def _parse_event_time(raw: str) -> datetime:
    """Parse ISO-8601 timestamp from the scored event payload."""
    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.now(timezone.utc)


def _produce_dlq(payload_bytes: bytes, error: str) -> None:
    """Best-effort DLQ write using a fresh producer.  Never raises."""
    try:
        from confluent_kafka import Producer
        import os as _os
        p = Producer({
            "bootstrap.servers": _os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
        })
        dlq_record = json.dumps({
            "topic":    _SCORED_EVENTS_TOPIC,
            "error":    error,
            "raw":      payload_bytes.decode("utf-8", errors="replace"),
        })
        p.produce(_PROFILE_DLQ_TOPIC, value=dlq_record)
        p.flush()
    except Exception as exc:
        logger.warning("[PROFILE_UPDATER] DLQ write failed: %s", exc)


def start_profile_updater() -> None:
    """
    Subscribe to fraud.scored.events and keep all risk profiles up to date.
    """
    consumer = Consumer(_KAFKA_CONFIG)
    consumer.subscribe([_SCORED_EVENTS_TOPIC])

    logger.info("[PROFILE_UPDATER] Subscribed to %s", _SCORED_EVENTS_TOPIC)

    try:
        while True:
            message = consumer.poll(timeout=1.0)

            if message is None:
                continue

            if message.error():
                logger.error("[PROFILE_UPDATER] Consumer error: %s", message.error())
                continue

            raw_bytes = message.value()
            db_connection = get_db_connection()

            try:
                payload = json.loads(raw_bytes.decode("utf-8"))

                subject_id      = payload["subject_id"]
                action_taxonomy = payload["action_taxonomy"]
                final_score     = int(payload["score"])
                event_id        = payload["event_id"]
                risk_level      = payload["risk_level"]
                action_taken    = payload.get("action_taken", "UNKNOWN")
                event_time      = _parse_event_time(payload.get("timestamp", ""))

                update_risk_profile(
                    db_connection,
                    subject_id=subject_id,
                    action_taxonomy=action_taxonomy,
                    final_score=final_score,
                    event_id=event_id,
                    event_time=event_time,
                    risk_level=risk_level,
                    action_taken=action_taken,
                )

                db_connection.commit()
                consumer.commit(message)

                logger.info(
                    "[PROFILE_UPDATER] Updated profile subject_id=%s taxonomy=%s score=%d risk=%s",
                    subject_id, action_taxonomy, final_score, risk_level,
                )

            except (KeyError, ValueError, json.JSONDecodeError) as exc:
                db_connection.rollback()
                logger.error("[PROFILE_UPDATER] Malformed message: %s", exc)
                _produce_dlq(raw_bytes, str(exc))

            except Exception as exc:
                db_connection.rollback()
                logger.exception("%s: Profile update failure", ErrorCode.KAFKA_ERROR)
                _produce_dlq(raw_bytes, str(exc))

            finally:
                release_db_connection(db_connection)

    except KeyboardInterrupt:
        logger.info("[PROFILE_UPDATER] Stopped by interrupt")

    finally:
        consumer.close()


if __name__ == "__main__":
    start_profile_updater()
