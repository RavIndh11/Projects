from fastapi.testclient import TestClient
from app.main import app
import io

client = TestClient(app)

def test_health_check():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_index_page():
    response = client.get("/")
    assert response.status_code == 200
    assert "API Shadow Hunter" in response.text

def test_analyze_endpoint_success():
    openapi_yaml = """
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /docs:
    get:
      summary: test
"""
    logs = "GET /docs\nGET /shadow"

    files = {
        'openapi_file': ('openapi.yaml', io.BytesIO(openapi_yaml.encode('utf-8')), 'application/x-yaml'),
        'log_file': ('logs.txt', io.BytesIO(logs.encode('utf-8')), 'text/plain'),
    }

    response = client.post("/analyze", files=files)
    assert response.status_code == 200

    # Check that the template renders correctly for success
    html = response.text
    assert "Endpoint Analysis Details" in html
    assert "GET" in html
    assert "/docs" in html
    assert "/shadow" in html
    assert "Documented" in html
    assert "Shadow" in html

def test_analyze_endpoint_invalid_yaml():
    openapi_yaml = "invalid: yaml: ["
    logs = "GET /docs"

    files = {
        'openapi_file': ('openapi.yaml', io.BytesIO(openapi_yaml.encode('utf-8')), 'application/x-yaml'),
        'log_file': ('logs.txt', io.BytesIO(logs.encode('utf-8')), 'text/plain'),
    }

    response = client.post("/analyze", files=files)
    assert response.status_code == 200

    html = response.text
    assert "Error Processing Data" in html
    assert "Failed to parse OpenAPI spec" in html
