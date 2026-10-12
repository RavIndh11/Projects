import logging
from pythonjsonlogger import jsonlogger
import sys
import os

def setup_logger():
    logger = logging.getLogger("secure_upload_gateway")

    # Check if handlers already exist to avoid duplicate logs in tests/reloads
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        logHandler = logging.StreamHandler(sys.stdout)

        # Use python-json-logger to format logs as JSON for SIEM compatibility
        formatter = jsonlogger.JsonFormatter(
            '%(asctime)s %(levelname)s %(name)s %(message)s',
            datefmt="%Y-%m-%dT%H:%M:%SZ"
        )
        logHandler.setFormatter(formatter)
        logger.addHandler(logHandler)

    return logger

logger = setup_logger()
