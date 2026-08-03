import pytest
from datetime import datetime
from app.models import CloudTrailEvent, UserIdentity
from app.analyzer import CloudTrailAnalyzer

@pytest.fixture
def analyzer():
    return CloudTrailAnalyzer()

def create_event(event_name, user_type="IAMUser", user_name="test-user"):
    return CloudTrailEvent(
        eventVersion="1.08",
        userIdentity=UserIdentity(type=user_type, userName=user_name),
        eventTime=datetime.utcnow(),
        eventSource="cloudtrail.amazonaws.com",
        eventName=event_name,
        awsRegion="us-east-1",
        sourceIPAddress="192.168.1.1",
        eventID="test-id",
        eventType="AwsApiCall"
    )

def test_detect_defense_evasion(analyzer):
    event = create_event("StopLogging")
    findings = analyzer.analyze([event])

    assert len(findings) == 1
    assert findings[0].severity == "Critical"
    assert findings[0].title == "Defense Evasion Detected"
    assert findings[0].eventName == "StopLogging"

def test_detect_privilege_escalation(analyzer):
    event = create_event("PutUserPolicy")
    findings = analyzer.analyze([event])

    assert len(findings) == 1
    assert findings[0].severity == "High"
    assert findings[0].title == "Potential Privilege Escalation"
    assert findings[0].eventName == "PutUserPolicy"

def test_detect_root_usage(analyzer):
    event = create_event("CreateUser", user_type="Root", user_name="Root")
    findings = analyzer.analyze([event])

    assert len(findings) == 1
    assert findings[0].severity == "High"
    assert findings[0].title == "Root Account Usage"
    assert findings[0].userName == "Root"

def test_benign_event(analyzer):
    event = create_event("DescribeInstances")
    findings = analyzer.analyze([event])

    assert len(findings) == 0
