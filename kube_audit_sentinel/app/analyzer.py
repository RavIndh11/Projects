import uuid
from datetime import datetime
from typing import List, Optional
from app.models import AuditEvent, Alert
from app.logger import logger

class DetectionRule:
    def __init__(self, name: str, severity: str, description: str):
        self.name = name
        self.severity = severity
        self.description = description

    def evaluate(self, event: AuditEvent) -> bool:
        raise NotImplementedError

class PodExecRule(DetectionRule):
    def __init__(self):
        super().__init__(
            name="Pod Exec",
            severity="High",
            description="Execution into a pod detected (kubectl exec)."
        )

    def evaluate(self, event: AuditEvent) -> bool:
        # Check if the verb is create and the subresource is exec
        if event.verb == "create" and event.objectRef:
            if event.objectRef.resource == "pods" and event.objectRef.subresource == "exec":
                return True
        return False

class AnonymousAccessRule(DetectionRule):
    def __init__(self):
        super().__init__(
            name="Anonymous Access",
            severity="Critical",
            description="Unauthenticated access attempt detected."
        )

    def evaluate(self, event: AuditEvent) -> bool:
        if event.user and event.user.username == "system:anonymous":
            # Ignore read-only paths typically allowed or health checks if needed
            # For strictness, any action by anonymous is flagged
            return True
        return False

class SecretsAccessRule(DetectionRule):
    def __init__(self):
        super().__init__(
            name="Secrets Access",
            severity="Medium",
            description="Access to Kubernetes Secrets detected."
        )

    def evaluate(self, event: AuditEvent) -> bool:
        # Avoid noisy service account reads if desired, but generally flag secret access
        if event.objectRef and event.objectRef.resource == "secrets":
            if event.verb in ["get", "list", "watch"]:
                # Consider ignoring standard controller accounts if too noisy
                if event.user.username and not event.user.username.startswith("system:serviceaccount:kube-system"):
                    return True
        return False

class PrivilegedRoleBindingRule(DetectionRule):
    def __init__(self):
        super().__init__(
            name="Privileged RoleBinding",
            severity="Critical",
            description="Creation or modification of a highly privileged ClusterRoleBinding/RoleBinding."
        )

    def evaluate(self, event: AuditEvent) -> bool:
        if event.verb in ["create", "update", "patch"] and event.objectRef:
            if event.objectRef.resource in ["clusterrolebindings", "rolebindings"]:
                # We would ideally check the requestObject for the actual role being bound.
                if event.requestObject and "roleRef" in event.requestObject:
                    role_ref = event.requestObject["roleRef"].get("name", "")
                    if role_ref in ["cluster-admin", "admin", "edit"]:
                        return True
        return False

class Analyzer:
    def __init__(self):
        self.rules: List[DetectionRule] = [
            PodExecRule(),
            AnonymousAccessRule(),
            SecretsAccessRule(),
            PrivilegedRoleBindingRule()
        ]
        self.alerts: List[Alert] = []

    def analyze_event(self, event: AuditEvent) -> Optional[List[Alert]]:
        triggered_alerts = []
        for rule in self.rules:
            try:
                if rule.evaluate(event):
                    alert = Alert(
                        id=str(uuid.uuid4()),
                        timestamp=datetime.utcnow().isoformat() + "Z",
                        rule_name=rule.name,
                        severity=rule.severity,
                        description=rule.description,
                        audit_id=event.auditID,
                        user=event.user.username or "unknown",
                        source_ips=event.sourceIPs or [],
                        resource=event.objectRef.resource if event.objectRef else "unknown",
                        namespace=event.objectRef.namespace if event.objectRef and event.objectRef.namespace else "cluster-scoped"
                    )
                    triggered_alerts.append(alert)
                    logger.info(f"Alert Triggered: {alert.rule_name}", extra={"extra_info": alert.model_dump()})
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.name}: {e}")

        self.alerts.extend(triggered_alerts)

        # Keep only the latest 100 alerts in memory
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-100:]

        return triggered_alerts

    def get_alerts(self) -> List[Alert]:
        return sorted(self.alerts, key=lambda x: x.timestamp, reverse=True)
