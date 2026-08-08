import logging
from pythonjsonlogger import jsonlogger
import sys

def setup_logger():
    _logger = logging.getLogger("ssrf_sentinel")
    _logger.setLevel(logging.INFO)

    if not _logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = jsonlogger.JsonFormatter(
            '%(asctime)s %(levelname)s %(name)s %(message)s'
        )
        handler.setFormatter(formatter)
        _logger.addHandler(handler)

    return _logger

logger = setup_logger()