import logging
from pythonjsonlogger import jsonlogger
from typing import List, Dict, Any
from datetime import datetime

log_storage: List[Dict[str, Any]] = []

class InMemoryHandler(logging.Handler):
    def emit(self, record):
        try:
            log_entry = self.format(record)
            import json
            parsed_entry = json.loads(log_entry)
            log_storage.insert(0, parsed_entry)
            if len(log_storage) > 100:
                log_storage.pop()
        except Exception:
            self.handleError(record)

def setup_logger():
    logger = logging.getLogger("policy_guard")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        console_handler = logging.StreamHandler()
        formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        memory_handler = InMemoryHandler()
        memory_handler.setFormatter(formatter)
        logger.addHandler(memory_handler)
    return logger

logger = setup_logger()

def get_recent_logs() -> List[Dict[str, Any]]:
    return log_storage

def clear_logs():
    log_storage.clear()
