import pytest
from httpx import Response
from app.scanner import run_scan

@pytest.mark.asyncio
async def test_run_scan_introspection_disabled(mocker):
    mock_post = mocker.patch("httpx.AsyncClient.post")
    # Simulate a response where introspection is disabled (no data or error)
    mock_post.return_value = Response(200, request=mocker.Mock(), json={"errors": [{"message": "GraphQL introspection is not allowed"}]})

    result = await run_scan("http://test.com/graphql")

    assert result.introspection_enabled == False
    assert len(result.vulnerabilities) == 0
    assert result.status == "completed"

@pytest.mark.asyncio
async def test_run_scan_introspection_enabled_no_sensitive(mocker):
    mock_post = mocker.patch("httpx.AsyncClient.post")
    mock_data = {
        "data": {
            "__schema": {
                "types": [
                    {
                        "name": "User",
                        "fields": [
                            {"name": "id"},
                            {"name": "username"}
                        ]
                    }
                ]
            }
        }
    }
    mock_post.return_value = Response(200, request=mocker.Mock(), json=mock_data)

    result = await run_scan("http://test.com/graphql")

    assert result.introspection_enabled == True
    assert len(result.vulnerabilities) == 1
    assert result.vulnerabilities[0].title == "GraphQL Introspection Enabled"
    assert len(result.sensitive_fields_found) == 0
    assert result.status == "completed"

@pytest.mark.asyncio
async def test_run_scan_introspection_enabled_with_sensitive(mocker):
    mock_post = mocker.patch("httpx.AsyncClient.post")
    mock_data = {
        "data": {
            "__schema": {
                "types": [
                    {
                        "name": "User",
                        "fields": [
                            {"name": "id"},
                            {"name": "password"},
                            {"name": "ssn"}
                        ]
                    }
                ]
            }
        }
    }
    mock_post.return_value = Response(200, request=mocker.Mock(), json=mock_data)

    result = await run_scan("http://test.com/graphql")

    assert result.introspection_enabled == True
    assert len(result.vulnerabilities) == 2  # Introspection + Sensitive fields

    titles = [v.title for v in result.vulnerabilities]
    assert "GraphQL Introspection Enabled" in titles
    assert "Sensitive Fields Exposed" in titles

    assert len(result.sensitive_fields_found) == 2
    assert "User.password" in result.sensitive_fields_found
    assert "User.ssn" in result.sensitive_fields_found
    assert result.status == "completed"

@pytest.mark.asyncio
async def test_run_scan_network_error(mocker):
    mock_post = mocker.patch("httpx.AsyncClient.post", side_effect=Exception("Connection failed"))

    result = await run_scan("http://test.com/graphql")

    assert result.status == "failed"
    assert result.error_message == "Connection failed"
