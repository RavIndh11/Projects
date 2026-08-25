import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.models import ScanResult

client = TestClient(app)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "GraphQL Inspector" in response.text

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_scan_endpoint(mocker):
    # Mock the run_scan function in the main module
    mock_run_scan = mocker.patch("app.main.run_scan")
    mock_run_scan.return_value = ScanResult(
        url="http://example.com/graphql",
        introspection_enabled=False,
        sensitive_fields_found=[],
        vulnerabilities=[],
        status="completed"
    )

    response = client.post("/scan", json={"url": "http://example.com/graphql"})

    assert response.status_code == 200
    data = response.json()
    assert data["url"] == "http://example.com/graphql"
    assert data["introspection_enabled"] == False
    assert data["status"] == "completed"


def test_scan_ui_endpoint(mocker):
    mock_run_scan = mocker.patch("app.main.run_scan")
    mock_run_scan.return_value = ScanResult(
        url="http://example.com/graphql",
        introspection_enabled=False,
        sensitive_fields_found=[],
        vulnerabilities=[],
        status="completed"
    )

    response = client.post("/scan_ui", data={"url": "http://example.com/graphql"})

    assert response.status_code == 200
    assert "Scan Results" in response.text
    assert "http://example.com/graphql" in response.text
