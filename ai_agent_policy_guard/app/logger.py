import logging
from pythonjsonlogger import jsonlogger
import sys
import os

def setup_logger():
    logger = logging.getLogger("ai_agent_policy_guard")
    # Only set up handler if one doesn't exist
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        logHandler = logging.StreamHandler(sys.stdout)

        formatter = jsonlogger.JsonFormatter(
            '%(asctime)s %(levelname)s %(name)s %(message)s'
        )
        logHandler.setFormatter(formatter)
        logger.addHandler(logHandler)

    return logger

logger = setup_logger()
