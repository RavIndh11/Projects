import logging
from pythonjsonlogger import jsonlogger

def setup_json_logger(name: str = "api_shadow_hunter") -> logging.Logger:
    logger = logging.getLogger(name)

    # Only configure if no handlers are present to avoid duplication
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        logHandler = logging.StreamHandler()
        formatter = jsonlogger.JsonFormatter(
            '%(asctime)s %(name)s %(levelname)s %(message)s'
        )
        logHandler.setFormatter(formatter)
        logger.addHandler(logHandler)

    return logger
