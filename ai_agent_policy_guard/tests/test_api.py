import pytest
from fastapi.testclient import TestClient
import yaml
import tempfile
import os
import shutil
from pathlib import Path

# Override the policy directory before importing main
temp_dir = tempfile.mkdtemp()
policy_path = os.path.join(temp_dir, "test_policy.yaml")
policy_data = {
    "agent_id": "test-agent",
    "allowed_tools": {
        "safe_tool": {}
    }
}
with open(policy_path, "w") as f:
    yaml.dump(policy_data, f)

# Patch the default policy dir
from app import main
main.policy_engine.policy_dir = Path(temp_dir)
main.policy_engine.policies = main.policy_engine.load_policies()

client = TestClient(main.app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_evaluate_allowed():
    payload = {
        "agent_id": "test-agent",
        "tool_name": "safe_tool",
        "arguments": {}
    }
    response = client.post("/evaluate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["allowed"] == True

def test_evaluate_denied():
    payload = {
        "agent_id": "test-agent",
        "tool_name": "unsafe_tool",
        "arguments": {}
    }
    response = client.post("/evaluate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["allowed"] == False

def test_dashboard():
    response = client.get("/")
    assert response.status_code == 200
    assert "AI Agent Policy Guard" in response.text

def teardown_module():
    shutil.rmtree(temp_dir)
