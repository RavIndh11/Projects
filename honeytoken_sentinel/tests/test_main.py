import os
import pytest
from fastapi.testclient import TestClient

import tempfile

# Setup test database
db_fd, db_path = tempfile.mkstemp(suffix=".db")
os.environ["DB_PATH"] = db_path

from app.main import app
from app import db

client = TestClient(app)

@pytest.fixture(scope="session", autouse=True)
def setup_db():
    # Force DB_PATH override for db module since it's already loaded
    db.DB_PATH = os.environ["DB_PATH"]
    import app.config
    app.config.DB_PATH = os.environ["DB_PATH"]

    db.init_db()
    yield

    os.close(db_fd)
    os.unlink(db_path)

@pytest.fixture(autouse=True)
def cleanup_tables():
    yield
    # clear tables
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM alerts")
        cursor.execute("DELETE FROM tokens")
        conn.commit()

def test_dashboard():
    response = client.get("/")
    assert response.status_code == 200
    assert "Honeytoken Sentinel" in response.text

def test_create_token():
    payload = {
        "name": "Test Token",
        "description": "A token for testing",
        "severity": "High"
    }
    response = client.post("/api/tokens", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Test Token"
    assert data["severity"] == "High"
    assert "id" in data
    return data["id"]

def test_create_token_invalid_name():
    payload = {
        "name": "Test Token!@#", # Invalid chars
        "description": "A token for testing",
        "severity": "High"
    }
    response = client.post("/api/tokens", json=payload)
    assert response.status_code == 422 # Pydantic validation error

def test_trigger_token():
    token_id = test_create_token()

    # Trigger it
    headers = {"User-Agent": "EvilBot/1.0"}
    response = client.get(f"/t/{token_id}", headers=headers)
    assert response.status_code == 404 # Should return a 404 decoy

    # Verify alert was created
    alerts_response = client.get("/api/alerts")
    alerts = alerts_response.json()
    assert len(alerts) > 0

    alert = alerts[0]
    assert alert["token_id"] == token_id
    assert alert["user_agent"] == "EvilBot/1.0"

def test_trigger_invalid_token():
    response = client.get("/t/invalid-token-123")
    assert response.status_code == 200 # Redirects
    # In test client, redirect returns the response directly if follow_redirects is true,
    # or 307. We can just check it doesn't crash.
