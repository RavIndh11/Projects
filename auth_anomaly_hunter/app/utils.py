import logging
from pythonjsonlogger import jsonlogger

def setup_logging():
    """
    Configure structured JSON logging for SIEM integration.
    """
    logger = logging.getLogger("auth_anomaly_hunter")
    logger.setLevel(logging.INFO)

    logHandler = logging.StreamHandler()
    formatter = jsonlogger.JsonFormatter('%(asctime)s %(name)s %(levelname)s %(message)s')
    logHandler.setFormatter(formatter)

    # Avoid adding multiple handlers if setup is called multiple times
    if not logger.handlers:
        logger.addHandler(logHandler)

    return logger
