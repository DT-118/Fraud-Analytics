import json

from confluent_kafka import Consumer
from core.context import Context
from core.errors import ErrorCode
from core.logger import logger
from kafka_producer import produce_dlq_event, produce_scored_event
from services.fraud_service import handle_fraud_event
from storage.db import get_db_connection

KAFKA_BOOTSTRAP_SERVERS = "84.46.255.66:9092"
AUTH_LOGIN_TOPIC = "auth.login.events"

KAFKA_CONSUMER_CONFIG = {
    "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
    "group.id": "fraud-auth-consumer-1",
    "auto.offset.reset": "earliest",
    "enable.auto.commit": False,
}


def start_kafka_consumer():
    """
    Consume login events from Kafka and run fraud detection.
    """
    consumer = Consumer(KAFKA_CONSUMER_CONFIG)
    consumer.subscribe([AUTH_LOGIN_TOPIC])

    print(f"[KAFKA] Listening on topic: {AUTH_LOGIN_TOPIC}")

    try:
        while True:
            message = consumer.poll(timeout=1.0)

            if message is None:
                continue

            if message.error():
                print(f"[KAFKA ERROR] {message.error()}")
                continue

            db_connection = get_db_connection()

            try:
                payload = json.loads(message.value().decode("utf-8"))
                event_context = Context(**payload)

                fraud_decision = handle_fraud_event(
                    event_context,
                    db_connection=db_connection,
                    source="KAFKA",
                    config_version="auth_rules_v1",
                )

                db_connection.commit()

                produce_scored_event(event_context, fraud_decision)

                consumer.commit(message)

            except Exception as exc:
                db_connection.rollback()
                print("[KAFKA][ERROR] Event sent to DLQ")
                logger.exception(f"{ErrorCode.KAFKA_ERROR}: Kafka processing failure")
                produce_dlq_event(message, str(exc))

            finally:
                db_connection.close()

    except KeyboardInterrupt:
        print("[KAFKA] Consumer stopped")

    finally:
        consumer.close()


start_kafka_consumer()
