from typing import List, Dict, Tuple
from app.models.schemas import LogEntry, Alert
from app.core.config import settings
from app.core.logger import setup_logger

logger = setup_logger(__name__)

# State management
# For a real implementation this should use a DB or Redis.
# Structure: { user_id: [ (timestamp, action) ] }
state_store: Dict[str, List[Tuple[float, str]]] = {}

# In-memory store for recent alerts (for the dashboard)
recent_alerts: List[Alert] = []

def analyze_logs(logs: List[LogEntry]) -> List[Alert]:
    alerts = []

    # Process sequentially for the prototype
    for log in logs:
        user_id = log.user_id
        action = log.action
        ts = log.timestamp.timestamp()

        if user_id not in state_store:
            state_store[user_id] = []

        state_store[user_id].append((ts, action))

        # Keep only logs within the threshold
        cutoff = ts - settings.FATIGUE_THRESHOLD_SECONDS
        state_store[user_id] = [e for e in state_store[user_id] if e[0] >= cutoff]

        # Analyze current window
        recent_logs = state_store[user_id]

        denied_ignored_count = sum(
            1 for e in recent_logs if e[1] in ["mfa_prompt_denied", "mfa_prompt_ignored"]
        )

        # Condition 1: High frequency of denied/ignored
        if denied_ignored_count >= settings.FATIGUE_COUNT_THRESHOLD:
            # Condition 2: Check if there's a subsequent accept
            # An accept makes it critical, regardless of order in the threshold window for this prototype
            has_accept = any(e[1] == "mfa_prompt_accepted" for e in recent_logs)

            severity = "Critical" if has_accept else "High"
            desc = (f"MFA Fatigue successful! {denied_ignored_count} denied/ignored prompts followed by an accepted prompt within {settings.FATIGUE_THRESHOLD_SECONDS}s."
                   if has_accept else
                   f"Potential MFA Fatigue attack. {denied_ignored_count} denied/ignored prompts within {settings.FATIGUE_THRESHOLD_SECONDS}s.")

            # Deduplicate similar alerts for the SAME event in this batch
            is_dup = False
            for existing_alert in alerts:
                if existing_alert.user_id == user_id:
                    # If we already have a Critical alert in this batch, don't add another High
                    if existing_alert.severity == "Critical":
                        is_dup = True
                        break
                    # If we have a High alert but now we have a Critical, we should upgrade it or just append the critical.
                    # For simplicity, we just won't add duplicate severity/desc.
                    if existing_alert.description == desc:
                        is_dup = True
                        break

            if not is_dup:
                alert = Alert(
                    user_id=user_id,
                    attack_detected=True,
                    severity=severity,
                    description=desc,
                    prompt_count=denied_ignored_count
                )

                # Remove any existing "High" alert for this user in this batch if we're now adding a "Critical"
                if severity == "Critical":
                    alerts = [a for a in alerts if not (a.user_id == user_id and a.severity == "High")]

                alerts.append(alert)

                recent_alerts.insert(0, alert)
                if len(recent_alerts) > 50:
                    recent_alerts.pop()

                logger.info("MFA fatigue alert generated", extra={"alert": alert.model_dump()})

                if has_accept:
                     state_store[user_id] = []

    return alerts
