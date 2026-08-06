import pytest
from app.analyzer import (
    _convert_path_to_regex,
    parse_openapi_spec,
    parse_logs,
    analyze_endpoints,
    _assign_severity
)
from app.schemas import EndpointCategory, Severity

def test_convert_path_to_regex():
    assert _convert_path_to_regex("/api/users") == "^/api/users$"
    assert _convert_path_to_regex("/api/users/{id}") == "^/api/users/[^/]+$"
    assert _convert_path_to_regex("/api/users/{user_id}/posts/{post_id}") == "^/api/users/[^/]+/posts/[^/]+$"

def test_parse_openapi_spec():
    yaml_content = """
    openapi: 3.0.0
    info:
      title: Test API
      version: 1.0.0
    paths:
      /users:
        get:
          summary: Get users
        post:
          summary: Create user
      /users/{id}:
        get:
          summary: Get user by ID
    """
    paths = parse_openapi_spec(yaml_content)
    assert len(paths) == 2

    path_users = next(p for p in paths if p.path == "/users")
    assert "GET" in path_users.methods
    assert "POST" in path_users.methods
    assert path_users.regex_pattern == "^/users$"

    path_user_id = next(p for p in paths if p.path == "/users/{id}")
    assert "GET" in path_user_id.methods
    assert path_user_id.regex_pattern == "^/users/[^/]+$"

def test_parse_logs():
    log_content = "GET /users\nPOST /users\nGET /users/123\nGET /admin"
    logs = parse_logs(log_content)
    assert len(logs) == 4
    assert logs[0].method == "GET"
    assert logs[0].path == "/users"
    assert logs[2].method == "GET"
    assert logs[2].path == "/users/123"

def test_assign_severity():
    assert _assign_severity("/admin/settings") == Severity.CRITICAL
    assert _assign_severity("/debug/vars") == Severity.CRITICAL
    assert _assign_severity("/metrics") == Severity.HIGH
    assert _assign_severity("/test/endpoint") == Severity.MEDIUM
    assert _assign_severity("/unknown") == Severity.LOW

def test_analyze_endpoints():
    yaml_content = """
    openapi: 3.0.0
    info:
      title: Test
      version: 1.0.0
    paths:
      /api/users:
        get:
          summary: test
      /api/users/{id}:
        get:
          summary: test
      /api/zombie:
        get:
          summary: unused
    """
    documented = parse_openapi_spec(yaml_content)

    log_content = "GET /api/users\nGET /api/users/123\nGET /admin\nPOST /api/users"
    logs = parse_logs(log_content)

    report = analyze_endpoints(documented, logs)

    assert report.total_logs == 4
    assert report.documented_count == 2 # GET /api/users, GET /api/users/123
    assert report.shadow_count == 2     # GET /admin, POST /api/users
    assert report.zombie_count == 1     # GET /api/zombie

    # Check specific endpoints
    shadow_admin = next(e for e in report.endpoints if e.path == "/admin")
    assert shadow_admin.category == EndpointCategory.SHADOW
    assert shadow_admin.severity == Severity.CRITICAL

    shadow_post_user = next(e for e in report.endpoints if e.path == "/api/users" and e.method == "POST")
    assert shadow_post_user.category == EndpointCategory.SHADOW
    assert shadow_post_user.severity == Severity.LOW

    zombie = next(e for e in report.endpoints if e.path == "/api/zombie")
    assert zombie.category == EndpointCategory.ZOMBIE
