import pytest
import os
import sys

# Add parent dir to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core import PolicyEvaluator, action_matches

def test_action_matches():
    assert action_matches("iam:CreateAccessKey", "iam:CreateAccessKey")
    assert action_matches("iam:*", "iam:CreateAccessKey")
    assert action_matches("*", "iam:CreateAccessKey")
    assert action_matches("s3:*", "s3:GetObject")

    assert not action_matches("iam:*", "s3:GetObject")
    assert not action_matches("s3:GetObject", "s3:PutObject")

def test_policy_evaluator_allow():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iam:CreateAccessKey"]
            }
        ]
    }
    evaluator = PolicyEvaluator(policy)
    assert evaluator.is_action_allowed("iam:CreateAccessKey")
    assert not evaluator.is_action_allowed("iam:CreateUser")

def test_policy_evaluator_deny_overrides_allow():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iam:*"]
            },
            {
                "Effect": "Deny",
                "Action": ["iam:CreateAccessKey"]
            }
        ]
    }
    evaluator = PolicyEvaluator(policy)
    assert not evaluator.is_action_allowed("iam:CreateAccessKey")
    assert evaluator.is_action_allowed("iam:CreateUser")

def test_scan_for_privesc_create_access_key():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iam:CreateAccessKey"]
            }
        ]
    }
    evaluator = PolicyEvaluator(policy)
    findings = evaluator.scan_for_privesc()
    assert "CreateAccessKey" in findings
    assert len(findings) == 1

def test_scan_for_privesc_passrole_ec2():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iam:PassRole", "ec2:RunInstances"]
            }
        ]
    }
    evaluator = PolicyEvaluator(policy)
    findings = evaluator.scan_for_privesc()
    assert "PassRoleWithEC2" in findings

def test_scan_for_privesc_wildcards():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iam:*", "ec2:*"]
            }
        ]
    }
    evaluator = PolicyEvaluator(policy)
    findings = evaluator.scan_for_privesc()
    # Should flag everything related to iam and ec2
    assert "CreateAccessKey" in findings
    assert "PassRoleWithEC2" in findings
    # Shouldn't flag lambda passrole because lambda isn't allowed
    assert "PassRoleWithLambda" not in findings

def test_scan_for_privesc_secure():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"]
            }
        ]
    }
    evaluator = PolicyEvaluator(policy)
    findings = evaluator.scan_for_privesc()
    assert len(findings) == 0
