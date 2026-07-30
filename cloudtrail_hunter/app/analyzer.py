from typing import List, Dict, Any
from .models import CloudTrailEvent, Finding
import json

class CloudTrailAnalyzer:
    def __init__(self):
        # Define some common malicious patterns
        self.defense_evasion_events = [
            "StopLogging",
            "DeleteTrail",
            "UpdateTrail",
            "DeleteFlowLogs",
            "DeleteEventBus",
            "DisableSecurityHub"
        ]

        self.privesc_events = [
            "PutUserPolicy",
            "PutGroupPolicy",
            "PutRolePolicy",
            "AttachUserPolicy",
            "AttachGroupPolicy",
            "AttachRolePolicy",
            "CreateAccessKey",
            "CreateLoginProfile",
            "UpdateLoginProfile"
        ]

        self.recon_events = [
            "DescribeTrails",
            "GetCallerIdentity",
            "ListUsers",
            "ListRoles",
            "ListBuckets"
        ]

    def analyze(self, events: List[CloudTrailEvent]) -> List[Finding]:
        findings = []
        for event in events:
            finding = self._analyze_event(event)
            if finding:
                findings.append(finding)
        return findings

    def _analyze_event(self, event: CloudTrailEvent) -> Finding | None:
        username = event.userIdentity.userName or "Unknown"
        if event.userIdentity.type == "Root":
            username = "Root"

        # Check for Defense Evasion
        if event.eventName in self.defense_evasion_events:
            return Finding(
                eventID=event.eventID,
                severity="Critical",
                title="Defense Evasion Detected",
                description=f"Action '{event.eventName}' attempted. This can indicate an attempt to disable logging or security monitoring.",
                eventTime=event.eventTime,
                eventName=event.eventName,
                eventSource=event.eventSource,
                sourceIPAddress=event.sourceIPAddress,
                userName=username
            )

        # Check for Privilege Escalation
        if event.eventName in self.privesc_events:
            return Finding(
                eventID=event.eventID,
                severity="High",
                title="Potential Privilege Escalation",
                description=f"Action '{event.eventName}' attempted. This may indicate an attempt to elevate privileges.",
                eventTime=event.eventTime,
                eventName=event.eventName,
                eventSource=event.eventSource,
                sourceIPAddress=event.sourceIPAddress,
                userName=username
            )

        # Check for Root usage
        if event.userIdentity.type == "Root" and event.eventName != "ConsoleLogin":
             return Finding(
                eventID=event.eventID,
                severity="High",
                title="Root Account Usage",
                description=f"Root account used to perform '{event.eventName}'. Root account usage should be heavily restricted.",
                eventTime=event.eventTime,
                eventName=event.eventName,
                eventSource=event.eventSource,
                sourceIPAddress=event.sourceIPAddress,
                userName="Root"
            )

        # Check ConsoleLogin failures / no MFA
        if event.eventName == "ConsoleLogin":
            response_elements = event.responseElements or {}
            console_login = response_elements.get("ConsoleLogin")
            if console_login == "Failure":
                 # Could be brute force but single failure is usually low
                 pass
            elif console_login == "Success":
                 additional_event_data = event.model_extra or {}
                 # Often MFA info is in additionalEventData.
                 # Let's check for basic login without MFA if possible.
                 pass

        return None
