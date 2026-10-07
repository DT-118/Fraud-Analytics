"""
kafka_consumer.py

Consumes fraud events from all four service topics:
  auth.events
  login.events
  consent.events
  wallet.events

All config is read from environment variables — no hardcoded addresses.
Required env vars:
  KAFKA_BOOTSTRAP_SERVERS  e.g. broker1:9092,broker2:9092
  KAFKA_GROUP_ID           e.g. fraud-engine-consumer (optional, defaults below)
"""

from dotenv import load_dotenv

load_dotenv()


import json
import os

from confluent_kafka import Consumer
from core.context import Context
from core.errors import ErrorCode
from core.logger import logger
from kafka_producer import produce_decision_event, produce_dlq_event, produce_scored_event
from service.fraud_service import handle_fraud_event
from storage.db import get_db_connection, release_db_connection

# All 4 service topics — Phase 2 expansion from AUTH-only
_TOPICS = [
    "auth.events",
    "login.events",
    "consent.events",
    "wallet.events",
]

_KAFKA_CONSUMER_CONFIG = {
    "bootstrap.servers": os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
    "group.id":          os.environ.get("KAFKA_GROUP_ID", "fraud-engine-consumer-1"),
    "auto.offset.reset": "earliest",
    "enable.auto.commit": False,
}

_CONFIG_VERSION = os.environ.get("CONFIG_VERSION", "rules_v2")


def start_kafka_consumer() -> None:
    """
    Subscribe to all service topics and run fraud scoring
    on every incoming event. Commits offset only after
    successful processing. Failed events go to DLQ.
    """
    consumer = Consumer(_KAFKA_CONSUMER_CONFIG)
    consumer.subscribe(_TOPICS)

    logger.info("[KAFKA] Subscribed to topics: %s", _TOPICS)

    try:
        while True:
            message = consumer.poll(timeout=1.0)

            if message is None:
                continue

            if message.error():
                logger.error("[KAFKA] Consumer error: %s", message.error())
                continue

            db_connection = get_db_connection()

            try:
                payload       = json.loads(message.value().decode("utf-8"))
                event_context = Context(**payload)

                fraud_decision = handle_fraud_event(
                    event_context,
                    db_connection=db_connection,
                    source="KAFKA",
                    config_version=_CONFIG_VERSION,
                )

                if fraud_decision.get("duplicate"):
                   db_connection.rollback()
                   logger.info("[KAFKA] Duplicate event_id=%s — skipped, offset committed",event_context.event_id)
                   consumer.commit(message)
                   continue

                db_connection.commit()

                # Publish to internal scored-events feed (profile updater + Splunk)
                produce_scored_event(event_context, fraud_decision)

                # Publish decision back to the originating service's dedicated topic
                produce_decision_event(event_context, fraud_decision)

                consumer.commit(message)
                logger.info(
                    "[KAFKA] Processed event_id=%s topic=%s score=%d",   
                    event_context.event_id,
                    message.topic(),
                    fraud_decision.get("score", 0),   
                )

            except Exception as exc:
                db_connection.rollback()
                logger.exception("%s: Kafka processing failure — routing to DLQ",
                                 ErrorCode.KAFKA_ERROR)
                dlq_ok = produce_dlq_event(message, str(exc))
                if dlq_ok:
                    # Message is durably quarantined — safe to advance past it.
                    consumer.commit(message)
                else:
                    logger.error(
                        "[KAFKA] DLQ write failed for a message that also failed "
                        "processing — offset NOT committed; will retry on next poll. "
                        "topic=%s partition=%s offset=%s",
                        message.topic(), message.partition(), message.offset(),
                    )

            finally:
                release_db_connection(db_connection)

    except KeyboardInterrupt:
        logger.info("[KAFKA] Consumer stopped by interrupt")

    finally:
        consumer.close()


if __name__ == "__main__":
    start_kafka_consumer()