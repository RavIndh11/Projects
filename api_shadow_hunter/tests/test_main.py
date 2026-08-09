import pytest
from fastapi.testclient import TestClient
from app.main import app, STATE
from app.analyzer import parse_openapi_spec, parse_access_logs, match_path, detect_shadow_zombie_apis

client = TestClient(app)

def setup_function():
    # Reset state before each test
    STATE["spec_endpoints"] = []
    STATE["log_traffic"] = []
    STATE["results"] = {"shadow_apis": [], "zombie_apis": []}

def test_parse_openapi_spec():
    yaml_content = """
    paths:
      /users:
        get: {}
        post: {}
      /users/{id}:
        get: {}
    """
    endpoints = parse_openapi_spec(yaml_content)
    assert len(endpoints) == 3
    assert {'path': '/users', 'method': 'GET'} in endpoints
    assert {'path': '/users', 'method': 'POST'} in endpoints
    assert {'path': '/users/{id}', 'method': 'GET'} in endpoints

def test_parse_access_logs():
    log_content = '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /users HTTP/1.0" 200 2326\n127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "POST /admin HTTP/1.0" 401 2326'
    traffic = parse_access_logs(log_content)
    assert len(traffic) == 2
    assert {'path': '/users', 'method': 'GET'} in traffic
    assert {'path': '/admin', 'method': 'POST'} in traffic

def test_match_path():
    assert match_path("/users/123", "/users/{id}") == True
    assert match_path("/users/123/profile", "/users/{id}") == False
    assert match_path("/users", "/users") == True
    assert match_path("/api/v1/users", "/api/v1/users") == True

def test_detect_shadow_zombie_apis():
    spec_endpoints = [
        {'path': '/users', 'method': 'GET'},
        {'path': '/users/{id}', 'method': 'GET'},
        {'path': '/old_endpoint', 'method': 'GET'} # Zombie
    ]

    log_traffic = [
        {'path': '/users', 'method': 'GET'},
        {'path': '/users/123', 'method': 'GET'},
        {'path': '/admin/login', 'method': 'POST'} # Shadow
    ]

    results = detect_shadow_zombie_apis(spec_endpoints, log_traffic)

    assert len(results['shadow_apis']) == 1
    assert results['shadow_apis'][0] == {'path': '/admin/login', 'method': 'POST'}

    assert len(results['zombie_apis']) == 1
    assert results['zombie_apis'][0] == {'path': '/old_endpoint', 'method': 'GET'}

def test_api_endpoints():
    # Test Dashboard
    response = client.get("/dashboard")
    assert response.status_code == 200

    # Test Spec Upload
    yaml_content = "paths:\n  /users:\n    get: {}"
    response = client.post(
        "/api/upload-spec",
        files={"file": ("spec.yaml", yaml_content, "text/yaml")}
    )
    assert response.status_code == 200
    assert response.json()["count"] == 1

    # Test Log Upload
    log_content = '127.0.0.1 - - "GET /users HTTP/1.0" 200\n127.0.0.1 - - "POST /admin HTTP/1.0" 401'
    response = client.post(
        "/api/upload-logs",
        files={"file": ("access.log", log_content, "text/plain")}
    )
    assert response.status_code == 200
    assert response.json()["count"] == 2

    # Verify State updated
    assert len(STATE["results"]["shadow_apis"]) == 1
    assert STATE["results"]["shadow_apis"][0]["path"] == "/admin"
    assert len(STATE["results"]["zombie_apis"]) == 0
