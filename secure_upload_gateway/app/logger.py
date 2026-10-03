import logging
import os
from pythonjsonlogger import jsonlogger

def setup_logger():
    logger = logging.getLogger("secure_upload_gateway")
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logger.setLevel(getattr(logging, log_level, logging.INFO))

    logHandler = logging.StreamHandler()
    formatter = jsonlogger.JsonFormatter(
        '%(asctime)s %(levelname)s %(name)s %(message)s'
    )
    logHandler.setFormatter(formatter)
    logger.addHandler(logHandler)

    # Avoid duplicate logs if the logger is retrieved multiple times
    logger.propagate = False
    return logger

logger = setup_logger()
