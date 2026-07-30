import pytest
from fastapi.testclient import TestClient
import json
from app.main import app

client = TestClient(app)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "CloudTrail Hunter" in response.text

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}

def test_analyze_invalid_file_type():
    files = {'file': ('test.txt', b'some content', 'text/plain')}
    response = client.post("/analyze", files=files)
    assert response.status_code == 200
    assert "Invalid file type. Please upload a JSON file." in response.text

def test_analyze_invalid_json():
    files = {'file': ('test.json', b'invalid json data', 'application/json')}
    response = client.post("/analyze", files=files)
    assert response.status_code == 200
    assert "Failed to parse JSON file" in response.text

def test_analyze_valid_cloudtrail():
    mock_log = {
        "Records": [
            {
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "IAMUser",
                    "userName": "attacker"
                },
                "eventTime": "2023-10-27T10:00:00Z",
                "eventSource": "cloudtrail.amazonaws.com",
                "eventName": "StopLogging",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "192.168.1.1",
                "eventID": "12345",
                "eventType": "AwsApiCall"
            }
        ]
    }

    files = {'file': ('test.json', json.dumps(mock_log).encode('utf-8'), 'application/json')}
    response = client.post("/analyze", files=files)

    assert response.status_code == 200
    assert "Defense Evasion Detected" in response.text
    assert "StopLogging" in response.text
