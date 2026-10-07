"""
kafka_producer.py

Kafka producer utilities for Fraud Engine.
"""
from dotenv import load_dotenv

load_dotenv()
import json
import os
from datetime import datetime, timezone

from confluent_kafka import Producer
from core.errors import ErrorCode
from core.logger import logger

KAFKA_PRODUCER_CONFIG = {
    "bootstrap.servers": os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
}

kafka_producer = Producer(KAFKA_PRODUCER_CONFIG)

SCORED_EVENTS_TOPIC = "fraud.scored.events"
DEAD_LETTER_TOPIC   = "fraud.events.DLQ"

_DECISION_TOPICS: dict[str, str] = {
    "auth":   "auth.fraud.decisions",
    "login":   "login.fraud.decisions",
    "consent": "consent.fraud.decisions",
    "wallet":  "wallet.fraud.decisions",
}


def produce_scored_event(event_context, fraud_decision):
    """
    Publish a successfully scored fraud event to Kafka.
    """
    try:
        payload = {
            "event_type":      f"{event_context.action_taxonomy.upper()}_SCORED",
            "event_id":        str(event_context.event_id),
            "subject_id":      event_context.subject_id,
            "action_taxonomy": event_context.action_taxonomy,
            "score":           fraud_decision["score"],
            "risk_level":      fraud_decision["risk_level"],
            #"action_taken":    fraud_decision.get("action_taken", "UNKNOWN"),
            "triggered_rules": fraud_decision["triggered_rules"],
            "timestamp":       datetime.now(timezone.utc).isoformat(),
        }

        kafka_producer.produce(
            topic=SCORED_EVENTS_TOPIC,
            value=json.dumps(payload),
        )
        # poll(0) triggers delivery callbacks without blocking
        kafka_producer.poll(0)

    except Exception:
        logger.exception(f"{ErrorCode.KAFKA_ERROR}: Scored event publish failed")


def produce_decision_event(event_context, fraud_decision: dict) -> None:
    """
    Publish the fraud decision back to the originating service's dedicated topic.
    """
    topic = _DECISION_TOPICS.get(event_context.action_taxonomy)
    if not topic:
        logger.warning(
            "[KAFKA] No decision topic for action_taxonomy=%s — skipping",
            event_context.action_taxonomy,
        )
        return

    try:
        payload = {
            "correlation_id":  event_context.correlation_id,
            "event_id":        str(event_context.event_id),
            "transaction_id":  event_context.transaction_id,
            "subject_id":      event_context.subject_id,
            "action_taxonomy": event_context.action_taxonomy,
            #"action_taken":    fraud_decision.get("action_taken", "UNKNOWN"),
            "risk_level":      fraud_decision.get("risk_level", "UNKNOWN"),
            "score":           fraud_decision.get("score", 0),
            "triggered_rules": fraud_decision.get("triggered_rules", []),
            "timestamp":       datetime.now(timezone.utc).isoformat(),
        }

        kafka_producer.produce(
            topic=topic,
            key=event_context.correlation_id,
            value=json.dumps(payload),
        )
        kafka_producer.poll(0)


        logger.info(
            "[KAFKA] Decision published topic=%s correlation_id=%s",  
            topic,
            event_context.correlation_id,
            #payload["action_taken"], 
        )

    except Exception:
        logger.exception(
            "%s: Decision event publish failed taxonomy=%s",
            ErrorCode.KAFKA_ERROR,
            event_context.action_taxonomy,
        )


def produce_dlq_event(kafka_message, error_message: str) -> bool:
    """
    Publish a failed Kafka message to the Dead Letter Queue (DLQ).
    Returns True if the DLQ write landed (offset is safe to commit),
   False otherwise (caller must NOT commit — message will be retried).
    """
    try:
        payload = {
            "original_topic": kafka_message.topic(),
            "partition":      kafka_message.partition(),
            "offset":         kafka_message.offset(),
            "error":          error_message,
            "raw_message":    kafka_message.value().decode("utf-8", errors="replace"),
            "failed_at":      datetime.now(timezone.utc).isoformat(),
        }

        kafka_producer.produce(
            topic=DEAD_LETTER_TOPIC,
            value=json.dumps(payload),
        )
        # flush DLQ synchronously — we want to know it landed before discarding
        kafka_producer.flush(timeout=5)
        return True

    except Exception:
        logger.exception(f"{ErrorCode.KAFKA_ERROR}: DLQ publish failure")
        return False