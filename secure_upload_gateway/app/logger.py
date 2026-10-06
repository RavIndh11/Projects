import logging
from pythonjsonlogger import jsonlogger

def setup_logger():
    logger = logging.getLogger("secure_upload_gateway")
    logger.setLevel(logging.INFO)

    # Avoid duplicate handlers if setup is called multiple times
    if not logger.handlers:
        logHandler = logging.StreamHandler()
        formatter = jsonlogger.JsonFormatter(
            '%(asctime)s %(levelname)s %(name)s %(message)s'
        )
        logHandler.setFormatter(formatter)
        logger.addHandler(logHandler)

    return logger

logger = setup_logger()
