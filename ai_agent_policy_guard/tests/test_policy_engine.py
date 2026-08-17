import pytest
import tempfile
import yaml
import os
from app.policy_engine import PolicyEngine

@pytest.fixture
def temp_policy_file():
    policy = {
        "default_action": "deny",
        "tools": {
            "test_tool_allow": {
                "action": "allow",
                "rules": []
            },
            "test_tool_deny": {
                "action": "deny"
            },
            "test_tool_regex": {
                "action": "allow",
                "rules": [
                    {
                        "name": "must_be_safe",
                        "parameter": "cmd",
                        "match_type": "regex",
                        "pattern": "^safe_.*",
                        "required": True
                    }
                ]
            },
            "test_tool_exact": {
                "action": "allow",
                "rules": [
                    {
                        "name": "must_be_exact",
                        "parameter": "mode",
                        "match_type": "exact",
                        "allowed_values": ["read", "write"]
                    }
                ]
            },
            "test_tool_regex_deny": {
                "action": "allow",
                "rules": [
                    {
                        "name": "deny_unsafe",
                        "parameter": "path",
                        "match_type": "regex_deny",
                        "pattern": "\\.\\./"
                    }
                ]
            }
        }
    }

    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f:
        yaml.dump(policy, f)
        filepath = f.name

    yield filepath

    if os.path.exists(filepath):
        os.remove(filepath)

def test_load_nonexistent_policy():
    engine = PolicyEngine("nonexistent.yaml")
    assert engine.policies["default_action"] == "deny"

def test_evaluate_undefined_tool(temp_policy_file):
    engine = PolicyEngine(temp_policy_file)
    allowed, reason, rule = engine.evaluate("unknown_tool", {})
    assert not allowed
    assert rule == "default_deny"

def test_evaluate_explicit_allow(temp_policy_file):
    engine = PolicyEngine(temp_policy_file)
    allowed, reason, rule = engine.evaluate("test_tool_allow", {})
    assert allowed
    assert rule == "tool_allow"

def test_evaluate_explicit_deny(temp_policy_file):
    engine = PolicyEngine(temp_policy_file)
    allowed, reason, rule = engine.evaluate("test_tool_deny", {})
    assert not allowed
    assert rule == "tool_deny"

def test_evaluate_regex_rule_pass(temp_policy_file):
    engine = PolicyEngine(temp_policy_file)
    allowed, reason, rule = engine.evaluate("test_tool_regex", {"cmd": "safe_command"})
    assert allowed
    assert rule == "policy_pass"

def test_evaluate_regex_rule_fail(temp_policy_file):
    engine = PolicyEngine(temp_policy_file)
    allowed, reason, rule = engine.evaluate("test_tool_regex", {"cmd": "unsafe_command"})
    assert not allowed
    assert rule == "must_be_safe"

def test_evaluate_missing_required_param(temp_policy_file):
    engine = PolicyEngine(temp_policy_file)
    allowed, reason, rule = engine.evaluate("test_tool_regex", {})
    assert not allowed
    assert rule == "must_be_safe"
    assert "missing" in reason

def test_evaluate_exact_match_pass(temp_policy_file):
    engine = PolicyEngine(temp_policy_file)
    allowed, reason, rule = engine.evaluate("test_tool_exact", {"mode": "read"})
    assert allowed
    assert rule == "policy_pass"

def test_evaluate_exact_match_fail(temp_policy_file):
    engine = PolicyEngine(temp_policy_file)
    allowed, reason, rule = engine.evaluate("test_tool_exact", {"mode": "delete"})
    assert not allowed
    assert rule == "must_be_exact"

def test_evaluate_regex_deny_pass(temp_policy_file):
    engine = PolicyEngine(temp_policy_file)
    # The regex_deny rule fails (blocks) if the pattern matches.
    # So to "pass" the evaluation, it must NOT match the pattern.
    allowed, reason, rule = engine.evaluate("test_tool_regex_deny", {"path": "/var/log/app.log"})
    assert allowed
    assert rule == "policy_pass"

def test_evaluate_regex_deny_fail(temp_policy_file):
    engine = PolicyEngine(temp_policy_file)
    # Pattern is \.\./ , so this should match the deny rule and be blocked.
    allowed, reason, rule = engine.evaluate("test_tool_regex_deny", {"path": "../../etc/passwd"})
    assert not allowed
    assert rule == "deny_unsafe"
