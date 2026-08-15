import pytest
from fastapi.testclient import TestClient
import os
import tempfile
import yaml

from app.main import app
from app.logger import clear_logs

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_teardown():
    # Setup: override API_KEY for testing
    os.environ["API_KEY"] = "test_api_key"

    # Create a temporary policy file
    policy = {
        "default_action": "deny",
        "tools": {
            "shell_execute": {
                "action": "allow",
                "rules": [
                    {
                        "name": "restrict_commands",
                        "parameter": "command",
                        "match_type": "regex",
                        "pattern": "^(ls|cat|echo|pwd) .*$",
                        "required": True
                    }
                ]
            }
        }
    }
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f:
        yaml.dump(policy, f)
        filepath = f.name

    os.environ["POLICY_PATH"] = filepath

    # Manually trigger lifespan startup events by creating a new instance of PolicyEngine
    # since TestClient doesn't run lifespan events by default in older versions
    with client:
        clear_logs()
        yield

    # Teardown
    if os.path.exists(filepath):
        os.remove(filepath)
    clear_logs()


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "policy_loaded": True}

def test_evaluate_tool_unauthorized():
    response = client.post(
        "/api/v1/evaluate",
        json={"tool_name": "shell_execute", "parameters": {"command": "ls -la"}}
    )
    assert response.status_code == 401

    response = client.post(
        "/api/v1/evaluate",
        headers={"X-API-Key": "wrong_key"},
        json={"tool_name": "shell_execute", "parameters": {"command": "ls -la"}}
    )
    assert response.status_code == 401

def test_evaluate_tool_allowed():
    response = client.post(
        "/api/v1/evaluate",
        headers={"X-API-Key": "test_api_key"},
        json={
            "tool_name": "shell_execute",
            "parameters": {"command": "ls -la"},
            "agent_id": "test_agent"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["allowed"] is True
    assert data["matched_rule"] == "policy_pass"

    # Check if it was logged
    logs_response = client.get("/api/v1/logs", headers={"X-API-Key": "test_api_key"})
    logs = logs_response.json()["logs"]
    assert len(logs) > 0
    assert logs[0]["tool_name"] == "shell_execute"
    assert logs[0]["is_allowed"] is True

def test_evaluate_tool_denied():
    response = client.post(
        "/api/v1/evaluate",
        headers={"X-API-Key": "test_api_key"},
        json={
            "tool_name": "shell_execute",
            "parameters": {"command": "rm -rf /"},
            "agent_id": "test_agent"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["allowed"] is False
    assert data["matched_rule"] == "restrict_commands"

def test_evaluate_tool_not_found():
    response = client.post(
        "/api/v1/evaluate",
        headers={"X-API-Key": "test_api_key"},
        json={
            "tool_name": "unknown_tool",
            "parameters": {},
            "agent_id": "test_agent"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["allowed"] is False
    assert data["matched_rule"] == "default_deny"

def test_get_policy():
    response = client.get("/api/v1/policy", headers={"X-API-Key": "test_api_key"})
    assert response.status_code == 200
    data = response.json()
    assert "policy" in data
    assert data["policy"]["default_action"] == "deny"

def test_dashboard_ui():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "AI Agent Policy Guard" in response.text
