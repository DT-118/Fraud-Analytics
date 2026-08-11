"""
Central application logger.
"""


from dotenv import load_dotenv

load_dotenv()
import logging
import os

_LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, _LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger("fraud-engine")
logger.setLevel(getattr(logging, _LOG_LEVEL, logging.INFO))
