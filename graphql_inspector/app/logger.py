import logging
import sys
from pythonjsonlogger import jsonlogger

logger = logging.getLogger("graphql_inspector")
logger.setLevel(logging.INFO)

# Structured JSON logging
logHandler = logging.StreamHandler(sys.stdout)
formatter = jsonlogger.JsonFormatter(
    '%(asctime)s %(levelname)s %(name)s %(message)s'
)
logHandler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(logHandler)
