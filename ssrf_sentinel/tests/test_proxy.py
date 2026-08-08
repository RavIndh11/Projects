import pytest
from app.core.proxy import safe_fetch

@pytest.mark.asyncio
async def test_safe_fetch_blocked_ip(monkeypatch):
    monkeypatch.setattr("app.core.security.resolve_hostname", lambda host: ["169.254.169.254"])

    result = await safe_fetch("http://169.254.169.254/")
    assert result["status"] == "blocked"
    assert "blocked IP" in result["reason"]
    assert result["status_code"] == 403

@pytest.mark.asyncio
async def test_safe_fetch_allowed(monkeypatch):
    monkeypatch.setattr("app.core.security.resolve_hostname", lambda host: ["93.184.216.34"])

    # Mock httpx response to avoid real network call in tests
    class MockResponse:
        status_code = 200
        text = "Example Domain"
        headers = {"Content-Type": "text/html"}

    class MockClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass
        async def request(self, *args, **kwargs):
            return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient", lambda **kwargs: MockClient())

    result = await safe_fetch("http://example.com")
    assert result["status"] == "allowed"
    assert result["status_code"] == 200
    assert result["content"] == "Example Domain"
