import yaml
import json
import re
from typing import List, Dict, Set, Tuple

def parse_openapi_spec(file_content: str) -> List[Dict[str, str]]:
    """
    Parses an OpenAPI spec (YAML or JSON) and extracts expected endpoints and methods.
    Returns a list of dictionaries with 'path' and 'method' keys.
    """
    try:
        spec = yaml.safe_load(file_content)
    except yaml.YAMLError:
        try:
            spec = json.loads(file_content)
        except json.JSONDecodeError:
            return []

    endpoints = []
    if not spec or 'paths' not in spec:
        return endpoints

    for path, methods in spec['paths'].items():
        if isinstance(methods, dict):
            for method, details in methods.items():
                if method.lower() in ['get', 'post', 'put', 'delete', 'patch', 'options', 'head']:
                    endpoints.append({'path': path, 'method': method.upper()})

    return endpoints

def parse_access_logs(log_content: str) -> List[Dict[str, str]]:
    """
    Parses access logs (Nginx/Apache Common Log Format or similar) to extract HTTP method and path.
    Returns a list of dictionaries with 'path' and 'method' keys.
    """
    traffic = []

    # Common log format regex: loosely matches Method and Path
    # e.g., "GET /api/users HTTP/1.1" or similar
    log_pattern = re.compile(r'"([A-Z]+)\s+([^\s?]+).*?"')

    for line in log_content.splitlines():
        match = log_pattern.search(line)
        if match:
            method, path = match.groups()
            traffic.append({'path': path, 'method': method})

    return traffic

def match_path(log_path: str, spec_path: str) -> bool:
    """
    Converts an OpenAPI path template (e.g., /users/{id}) to a regex and checks if log_path matches.
    """
    # Replace path parameters with a regex that matches anything except a slash
    # e.g., /users/{id} -> /users/[^/]+
    regex_pattern = re.sub(r'\{[^}]+\}', r'[^/]+', spec_path)

    # Add start and end anchors
    regex_pattern = f"^{regex_pattern}$"

    try:
        return bool(re.match(regex_pattern, log_path))
    except re.error:
        return False

def detect_shadow_zombie_apis(spec_endpoints: List[Dict[str, str]], log_traffic: List[Dict[str, str]]) -> Dict[str, List[Dict[str, str]]]:
    """
    Categorizes endpoints as "Shadow APIs" or "Zombie APIs".
    """
    # Unique log paths/methods
    unique_traffic = {(item['method'], item['path']) for item in log_traffic}

    shadow_apis = []
    zombie_apis = []

    matched_spec_endpoints = set()

    for log_method, log_path in unique_traffic:
        is_matched = False
        for spec_endpoint in spec_endpoints:
            if spec_endpoint['method'] == log_method and match_path(log_path, spec_endpoint['path']):
                is_matched = True
                matched_spec_endpoints.add((spec_endpoint['method'], spec_endpoint['path']))
                break # Matched this log entry to a spec endpoint

        if not is_matched:
            shadow_apis.append({'method': log_method, 'path': log_path})

    for spec_endpoint in spec_endpoints:
        if (spec_endpoint['method'], spec_endpoint['path']) not in matched_spec_endpoints:
            zombie_apis.append({'method': spec_endpoint['method'], 'path': spec_endpoint['path']})

    return {
        'shadow_apis': shadow_apis,
        'zombie_apis': zombie_apis
    }
