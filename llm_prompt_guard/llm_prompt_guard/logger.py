import logging
import json
import sys
from datetime import datetime
import datetime as dt_module

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": datetime.now(dt_module.timezone.utc).isoformat() ,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add any extra attributes passed to the logger
        if hasattr(record, "extra_info"):
            log_entry.update(record.extra_info)

        return json.dumps(log_entry)

def setup_logger(name: str = "LLMPromptGuard") -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # Avoid adding handlers multiple times if logger is instantiated repeatedly
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = JSONFormatter()
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
