import os
import logging
from pythonjsonlogger import jsonlogger

DB_PATH = os.getenv("DB_PATH", "honeytoken.db")

def setup_logging():
    logger = logging.getLogger("honeytoken_sentinel")
    logger.setLevel(logging.INFO)

    # Remove existing handlers
    while logger.handlers:
        logger.handlers.pop()

    handler = logging.StreamHandler()
    formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

logger = setup_logging()
