import os
import psycopg2
from core.errors import ErrorCode
from core.logger import logger


def get_db_connection():
    """
    Create and return a PostgreSQL database connection.

    Connection parameters are loaded from environment variables
    to support different deployment environments.
    """
    try:
        logger.info("Creating database connection")
        print("[DB] Connecting to PostgreSQL")

        return psycopg2.connect(
            host=os.getenv("DB_HOST", "84.46.255.66"),
            port=os.getenv("DB_PORT", "5432"),
            dbname=os.getenv("DB_NAME", "fraud_management"),
            user=os.getenv("DB_USER", "postgres"),
            password=os.getenv("DB_PASSWORD", "Admin@753"),
        )

    except Exception as exc:
        logger.exception(
            "FE-501:DATABASE_CONNECTION_FAILED",
        )
        print("[DB ERROR] Failed to connect to database:", exc)
        raise RuntimeError(ErrorCode.DB_ERROR)
