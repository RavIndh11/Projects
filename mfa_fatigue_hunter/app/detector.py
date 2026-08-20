import time
import uuid
from typing import Dict, List, Optional
from app.models import AuthEvent, Alert
from pythonjsonlogger import jsonlogger
import logging
import sys

# Configure structured JSON logging
logger = logging.getLogger("mfa_fatigue_hunter")
logger.setLevel(logging.INFO)
logHandler = logging.StreamHandler(sys.stdout)
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(message)s')
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)

class MFAFatigueDetector:
    def __init__(self, time_window_seconds: int = 300, fatigue_threshold: int = 5):
        self.time_window = time_window_seconds
        self.fatigue_threshold = fatigue_threshold
        # Stores lists of timestamps of mfa_prompt events for each user
        self.user_prompts: Dict[str, List[float]] = {}
        # Keep track of the timestamp of the last fatigue alert for each user
        self.active_fatigue_alerts: Dict[str, float] = {}

    def process_event(self, event: AuthEvent) -> Optional[Alert]:
        current_time = event.timestamp
        email = event.user_email

        if event.event_type == "mfa_prompt":
            return self._handle_prompt(email, current_time)
        elif event.event_type == "mfa_success":
            return self._handle_success(email, current_time)
        elif event.event_type == "mfa_denied":
            self._handle_denied(email)

        return None

    def _cleanup_old_prompts(self, email: str, current_time: float):
        if email in self.user_prompts:
            self.user_prompts[email] = [
                t for t in self.user_prompts[email]
                if current_time - t <= self.time_window
            ]

    def _handle_prompt(self, email: str, current_time: float) -> Optional[Alert]:
        if email not in self.user_prompts:
            self.user_prompts[email] = []

        self.user_prompts[email].append(current_time)
        self._cleanup_old_prompts(email, current_time)

        prompt_count = len(self.user_prompts[email])

        if prompt_count >= self.fatigue_threshold:
            self.active_fatigue_alerts[email] = current_time
            logger.warning("MFA fatigue attack detected", extra={
                "user_email": email,
                "prompt_count": prompt_count,
                "time_window": self.time_window
            })
            return Alert(
                id=str(uuid.uuid4()),
                user_email=email,
                severity="High",
                description=f"Possible MFA Fatigue Attack: {prompt_count} prompts within {self.time_window} seconds."
            )
        return None

    def _handle_success(self, email: str, current_time: float) -> Optional[Alert]:
        # Clear prompts on success to reset counting if this is a legitimate login
        # (Though in a real scenario we might just clear prompts older than now)
        if email in self.user_prompts:
            self.user_prompts[email].clear()

        # Check if this success occurred recently after a fatigue attack
        last_fatigue_time = self.active_fatigue_alerts.get(email)
        if last_fatigue_time and (current_time - last_fatigue_time <= self.time_window):
            # This is a critical security event: prompt bombing succeeded!
            del self.active_fatigue_alerts[email]
            logger.error("MFA prompt bombing SUCCESSFUL", extra={
                "user_email": email
            })
            return Alert(
                id=str(uuid.uuid4()),
                user_email=email,
                severity="Critical",
                description="SUCCESSFUL MFA PROMPT BOMBING: User accepted MFA after experiencing a fatigue attack."
            )
        return None

    def _handle_denied(self, email: str):
        # A denied event indicates the user rejected it.
        # We don't reset the fatigue state or prompts because the attacker might keep trying.
        # We log it, but no new alert is necessarily generated just for a deny.
        logger.info("MFA prompt denied", extra={"user_email": email})
