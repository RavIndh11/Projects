import logging
from pythonjsonlogger import jsonlogger
import sys

def setup_logger():
    logger = logging.getLogger("mfa_fatigue_hunter")
    logger.setLevel(logging.INFO)

    # Avoid adding handlers multiple times if setup is called again
    if not logger.handlers:
        logHandler = logging.StreamHandler(sys.stdout)

        # Ensure scan_filename is used instead of filename to avoid conflicts as per instructions
        formatter = jsonlogger.JsonFormatter(
            '%(asctime)s %(levelname)s %(name)s %(message)s'
        )
        logHandler.setFormatter(formatter)
        logger.addHandler(logHandler)

    return logger

logger = setup_logger()
