"""
kafka_producer.py

Kafka producer utilities for Fraud Engine.
"""

import json
from confluent_kafka import Producer
from datetime import datetime, timezone
from core.errors import ErrorCode
from core.logger import logger

KAFKA_PRODUCER_CONFIG = {"bootstrap.servers": "84.46.255.66:9092"}

kafka_producer = Producer(KAFKA_PRODUCER_CONFIG)

SCORED_EVENTS_TOPIC = "fraud.scored.events"
DEAD_LETTER_TOPIC = "auth.login.events.DLQ"


def produce_scored_event(event_context, fraud_decision):
    """
    Publish a successfully scored fraud event to Kafka.
    """
    try:
        payload = {
            "event_type": "AUTH_LOGIN_SCORED",
            "event_id": str(event_context.event_id),
            "subject_id": event_context.subject_id,
            "score": fraud_decision["score"],
            "risk_level": fraud_decision["risk_level"],
            "triggered_rules": fraud_decision["triggered_rules"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        kafka_producer.produce(
            topic=SCORED_EVENTS_TOPIC,
            value=json.dumps(payload),
        )

        kafka_producer.flush()

    except Exception:
        print("[KAFKA][ERROR] Failed to produce scored event")
        logger.exception(f"{ErrorCode.KAFKA_ERROR}: Scored event publish failed")


def produce_dlq_event(kafka_message, error_message: str):
    """
    Publish a failed Kafka message to the Dead Letter Queue (DLQ).
    """
    try:
        payload = {
            "original_topic": kafka_message.topic(),
            "partition": kafka_message.partition(),
            "offset": kafka_message.offset(),
            "error": error_message,
            "raw_message": kafka_message.value().decode("utf-8", errors="replace"),
            "failed_at": datetime.now(timezone.utc).isoformat(),
        }

        kafka_producer.produce(
            topic=DEAD_LETTER_TOPIC,
            value=json.dumps(payload),
        )

        kafka_producer.flush()

    except Exception:
        print("[KAFKA][ERROR] Failed to publish DLQ event")
        logger.exception(f"{ErrorCode.KAFKA_ERROR}: DLQ publish failure")
