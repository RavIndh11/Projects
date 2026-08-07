import pytest
from analyzer import SpecParser, LogParser, APIAnalyzer

def test_spec_parser_yaml():
    spec_yaml = """
openapi: 3.0.0
paths:
  /users:
    get:
      summary: List users
    post:
      summary: Create user
  /users/{id}:
    get:
      summary: Get user
"""
    endpoints = SpecParser.parse(spec_yaml)
    assert len(endpoints) == 3
    assert ("GET", "/users") in endpoints
    assert ("POST", "/users") in endpoints
    assert ("GET", "/users/{param}") in endpoints

def test_spec_parser_json():
    spec_json = """
    {
      "openapi": "3.0.0",
      "paths": {
        "/api/v1/health": {
          "get": {}
        }
      }
    }
    """
    endpoints = SpecParser.parse(spec_json)
    assert len(endpoints) == 1
    assert ("GET", "/api/v1/health") in endpoints

def test_log_parser_json_format():
    logs = """
    {"method": "GET", "path": "/users"}
    {"http_method": "POST", "request_path": "/api/data?q=1"}
    {"method": "DELETE", "path": "/users/12345"}
    """
    endpoints = LogParser.parse(logs)
    assert len(endpoints) == 3
    assert ("GET", "/users") in endpoints
    assert ("POST", "/api/data") in endpoints
    assert ("DELETE", "/users/{param}") in endpoints

def test_log_parser_text_format():
    logs = """
    127.0.0.1 - - [10/Oct/2023] "GET /users HTTP/1.1" 200 123
    127.0.0.1 - - [10/Oct/2023] "PUT /users/550e8400-e29b-41d4-a716-446655440000 HTTP/1.1" 200 123
    """
    endpoints = LogParser.parse(logs)
    assert len(endpoints) == 2
    assert ("GET", "/users") in endpoints
    assert ("PUT", "/users/{param}") in endpoints

def test_analyzer():
    spec_yaml = """
openapi: 3.0.0
paths:
  /users:
    get:
      summary: List users
  /admin:
    get:
      summary: Admin panel (Zombie)
"""
    logs = """
    {"method": "GET", "path": "/users"}
    {"method": "POST", "path": "/users"}
    {"method": "GET", "path": "/hidden"}
    """

    result = APIAnalyzer.analyze(spec_yaml, logs)

    assert result.total_documented == 2
    assert result.total_accessed == 3

    # Check Shadow APIs (in logs, not in spec)
    shadow_paths = [api.path for api in result.shadow_apis]
    assert "/hidden" in shadow_paths
    assert "/users" in shadow_paths # POST is shadow

    shadow_methods = [api.method for api in result.shadow_apis if api.path == "/users"]
    assert "POST" in shadow_methods

    # Check Zombie APIs (in spec, not in logs)
    zombie_paths = [api.path for api in result.zombie_apis]
    assert "/admin" in zombie_paths
    assert len(result.zombie_apis) == 1
