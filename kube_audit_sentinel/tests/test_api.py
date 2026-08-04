import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}

def test_analyze_event_single():
    payload = {
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "level": "RequestResponse",
        "auditID": "1111-2222",
        "stage": "ResponseComplete",
        "requestURI": "/api/v1/namespaces/default/pods",
        "verb": "create",
        "user": {
            "username": "system:anonymous"
        },
        "objectRef": {
            "resource": "pods",
            "namespace": "default",
            "name": "test-pod"
        }
    }

    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "success"
    assert data["processed_events"] == 1
    assert data["alerts_generated"] >= 1

def test_analyze_event_list():
    payload = {
        "kind": "EventList",
        "apiVersion": "audit.k8s.io/v1",
        "items": [
            {
                "kind": "Event",
                "apiVersion": "audit.k8s.io/v1",
                "level": "Metadata",
                "auditID": "3333-4444",
                "stage": "ResponseComplete",
                "requestURI": "/api/v1/secrets",
                "verb": "get",
                "user": {
                    "username": "hacker"
                },
                "objectRef": {
                    "resource": "secrets"
                }
            }
        ]
    }

    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "success"
    assert data["processed_events"] == 1
    assert data["alerts_generated"] >= 1

def test_get_alerts():
    response = client.get("/api/v1/alerts")
    assert response.status_code == 200
    data = response.json()
    assert "alerts" in data
    assert isinstance(data["alerts"], list)

def test_dashboard():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Kube Audit Sentinel Dashboard" in response.text
