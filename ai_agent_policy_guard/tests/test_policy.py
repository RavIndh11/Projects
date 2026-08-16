import pytest
import yaml
import tempfile
import os
from pathlib import Path

from app.policy import PolicyEngine
from app.schemas import ToolExecutionRequest

@pytest.fixture
def temp_policy_dir():
    with tempfile.TemporaryDirectory() as temp_dir:
        policy_path = os.path.join(temp_dir, "test_policy.yaml")
        policy_data = {
            "agent_id": "agent-123",
            "denied_tools": ["delete_database"],
            "allowed_tools": {
                "read_file": {
                    "required_args": ["filepath"],
                    "arg_constraints": {
                        "filepath": "^/app/data/.*\\.txt$"
                    }
                },
                "list_files": {}
            }
        }
        with open(policy_path, "w") as f:
            yaml.dump(policy_data, f)
        yield temp_dir

def test_policy_engine_allowed(temp_policy_dir):
    engine = PolicyEngine(policy_dir=temp_policy_dir)
    req = ToolExecutionRequest(
        agent_id="agent-123",
        tool_name="read_file",
        arguments={"filepath": "/app/data/test.txt"}
    )
    result = engine.evaluate(req)
    assert result.allowed == True
    assert result.matched_rule == "allow"

def test_policy_engine_denied_tool(temp_policy_dir):
    engine = PolicyEngine(policy_dir=temp_policy_dir)
    req = ToolExecutionRequest(
        agent_id="agent-123",
        tool_name="delete_database",
        arguments={}
    )
    result = engine.evaluate(req)
    assert result.allowed == False
    assert result.matched_rule == "global_deny"

def test_policy_engine_missing_arg(temp_policy_dir):
    engine = PolicyEngine(policy_dir=temp_policy_dir)
    req = ToolExecutionRequest(
        agent_id="agent-123",
        tool_name="read_file",
        arguments={}
    )
    result = engine.evaluate(req)
    assert result.allowed == False
    assert result.matched_rule == "require_filepath"

def test_policy_engine_constraint_fail(temp_policy_dir):
    engine = PolicyEngine(policy_dir=temp_policy_dir)
    req = ToolExecutionRequest(
        agent_id="agent-123",
        tool_name="read_file",
        arguments={"filepath": "/etc/passwd"}
    )
    result = engine.evaluate(req)
    assert result.allowed == False
    assert result.matched_rule == "constraint_filepath"

def test_policy_engine_unknown_agent(temp_policy_dir):
    engine = PolicyEngine(policy_dir=temp_policy_dir)
    req = ToolExecutionRequest(
        agent_id="agent-404",
        tool_name="list_files",
        arguments={}
    )
    result = engine.evaluate(req)
    assert result.allowed == False
    assert result.matched_rule == None
