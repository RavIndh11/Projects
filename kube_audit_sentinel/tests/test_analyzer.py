import pytest
from app.models import AuditEvent, UserInfo, ObjectReference
from app.analyzer import (
    Analyzer,
    PodExecRule,
    AnonymousAccessRule,
    SecretsAccessRule,
    PrivilegedRoleBindingRule
)

def create_base_event() -> AuditEvent:
    return AuditEvent(
        level="RequestResponse",
        auditID="12345",
        stage="ResponseComplete",
        requestURI="/api/v1/namespaces/default/pods/test-pod",
        verb="get",
        user=UserInfo(username="test-user")
    )

def test_pod_exec_rule():
    rule = PodExecRule()
    event = create_base_event()
    event.verb = "create"
    event.objectRef = ObjectReference(resource="pods", subresource="exec")

    assert rule.evaluate(event) is True

    # Negative test
    event.verb = "get"
    assert rule.evaluate(event) is False

def test_anonymous_access_rule():
    rule = AnonymousAccessRule()
    event = create_base_event()
    event.user = UserInfo(username="system:anonymous")

    assert rule.evaluate(event) is True

    # Negative test
    event.user = UserInfo(username="admin")
    assert rule.evaluate(event) is False

def test_secrets_access_rule():
    rule = SecretsAccessRule()
    event = create_base_event()
    event.verb = "get"
    event.objectRef = ObjectReference(resource="secrets")

    assert rule.evaluate(event) is True

    # Negative test (kube-system service account)
    event.user = UserInfo(username="system:serviceaccount:kube-system:default")
    assert rule.evaluate(event) is False

def test_privileged_role_binding_rule():
    rule = PrivilegedRoleBindingRule()
    event = create_base_event()
    event.verb = "create"
    event.objectRef = ObjectReference(resource="clusterrolebindings")
    event.requestObject = {"roleRef": {"name": "cluster-admin"}}

    assert rule.evaluate(event) is True

    # Negative test (non-privileged role)
    event.requestObject = {"roleRef": {"name": "view"}}
    assert rule.evaluate(event) is False

def test_analyzer():
    analyzer = Analyzer()
    event = create_base_event()
    event.user = UserInfo(username="system:anonymous")

    alerts = analyzer.analyze_event(event)
    assert len(alerts) == 1
    assert alerts[0].rule_name == "Anonymous Access"
    assert alerts[0].severity == "Critical"

    all_alerts = analyzer.get_alerts()
    assert len(all_alerts) == 1
