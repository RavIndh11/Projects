import logging
from pythonjsonlogger import jsonlogger
import sys
import os

def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)

    # Only configure if not already configured to avoid duplicate handlers
    if not logger.handlers:
        logger.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())

        handler = logging.StreamHandler(sys.stdout)

        # Define the fields to include in the JSON output
        # Important: using scan_filename instead of filename to avoid conflicts with python's internal filename
        formatter = jsonlogger.JsonFormatter(
            '%(asctime)s %(levelname)s %(name)s %(message)s %(scan_filename)s'
        )

        handler.setFormatter(formatter)
        logger.addHandler(handler)

        # Prevent propagation to avoid duplicate logs in some frameworks
        logger.propagate = False

    return logger
