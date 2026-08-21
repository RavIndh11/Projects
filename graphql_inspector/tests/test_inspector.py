import pytest
from httpx import AsyncClient, Response
from app.main import app
from app.core import extract_sensitive_fields, extract_mutations, calculate_severity
from app.models import ThreatSeverity

# Mocking external HTTP requests
@pytest.fixture
def mock_httpx_post(mocker):
    return mocker.patch("httpx.AsyncClient.post")

@pytest.mark.asyncio
async def test_ui_index():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "GraphQL Inspector" in response.text

def test_extract_sensitive_fields():
    schema = {
        "types": [
            {
                "name": "User",
                "fields": [
                    {"name": "id"},
                    {"name": "username"},
                    {"name": "password"},
                    {"name": "apiToken"}
                ]
            },
            {
                "name": "Query",
                "fields": [{"name": "getUser"}]
            }
        ]
    }

    fields = extract_sensitive_fields(schema)
    assert len(fields) == 2
    assert "User.password" in fields
    assert "User.apiToken" in fields

def test_extract_mutations():
    schema = {
        "mutationType": {"name": "Mutation"},
        "types": [
            {
                "name": "Mutation",
                "fields": [
                    {"name": "createUser"},
                    {"name": "deleteUser"}
                ]
            }
        ]
    }

    mutations = extract_mutations(schema)
    assert len(mutations) == 2
    assert "createUser" in mutations
    assert "deleteUser" in mutations

def test_calculate_severity():
    assert calculate_severity(False, [], []) == ThreatSeverity.LOW
    assert calculate_severity(True, [], []) == ThreatSeverity.LOW
    assert calculate_severity(True, ["User.password"], []) == ThreatSeverity.HIGH
    assert calculate_severity(True, [], ["createUser"]) == ThreatSeverity.MEDIUM
    assert calculate_severity(True, ["User.password"], ["createUser"]) == ThreatSeverity.CRITICAL

@pytest.mark.asyncio
async def test_analyze_endpoint_disabled(mocker):
    # Instead of mocking httpx.AsyncClient.post globally, let's mock it inside app.core
    mock_fetch = mocker.patch("app.core.fetch_schema", return_value=(False, {}, "Introspection is likely disabled (GraphQL errors returned)."))

    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post("/api/analyze", json={"url": "https://api.example.com/graphql"})

    assert response.status_code == 200
    data = response.json()
    assert data["introspection_enabled"] is False
    assert data["severity"] == ThreatSeverity.LOW

@pytest.mark.asyncio
async def test_analyze_endpoint_enabled_critical(mocker):
    schema = {
        "mutationType": {"name": "Mutation"},
        "types": [
            {
                "name": "User",
                "fields": [
                    {"name": "password"}
                ]
            },
            {
                "name": "Mutation",
                "fields": [
                    {"name": "createUser"}
                ]
            }
        ]
    }
    mock_fetch = mocker.patch("app.core.fetch_schema", return_value=(True, schema, None))

    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post("/api/analyze", json={"url": "https://api.example.com/graphql"})

    assert response.status_code == 200
    data = response.json()
    assert data["introspection_enabled"] is True
    assert "User.password" in data["sensitive_fields"]
    assert "createUser" in data["mutations"]
    assert data["severity"] == ThreatSeverity.CRITICAL
