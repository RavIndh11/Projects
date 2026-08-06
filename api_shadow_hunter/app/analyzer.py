import re
import yaml
from typing import List, Dict, Tuple
from app.schemas import (
    AnalyzedEndpoint,
    AnalysisReport,
    EndpointCategory,
    Severity,
    OpenAPIPath,
    LogEntry
)

def _convert_path_to_regex(path: str) -> str:
    """
    Converts an OpenAPI path like /api/v1.0/users/{id} to a regex pattern like ^/api/v1\.0/users/[^/]+$
    """
    # First, escape regex special characters (except {} which we process next)
    # The common ones in paths are . + * ? ^ $ ( ) [ ] |
    # We do not want to escape { or } since we use them to find parameters

    # We'll safely split the string, escape fixed parts, and keep {}
    parts = re.split(r'(\{[^}]+\})', path)
    regex_parts = []
    for part in parts:
        if part.startswith('{') and part.endswith('}'):
            regex_parts.append('[^/]+')
        else:
            regex_parts.append(re.escape(part))

    pattern = ''.join(regex_parts)
    return f"^{pattern}$"

def parse_openapi_spec(spec_content: str) -> List[OpenAPIPath]:
    """
    Parses an OpenAPI spec (YAML or JSON string) and returns a list of documented paths.
    """
    try:
        spec = yaml.safe_load(spec_content)
    except yaml.YAMLError as e:
        raise ValueError(f"Failed to parse OpenAPI spec: {e}")

    paths_data = spec.get("paths", {})
    documented_paths = []

    for path, methods_data in paths_data.items():
        methods = [method.upper() for method in methods_data.keys() if method.lower() in
                   ['get', 'post', 'put', 'delete', 'patch', 'options', 'head', 'trace']]
        if methods:
            documented_paths.append(
                OpenAPIPath(
                    path=path,
                    methods=methods,
                    regex_pattern=_convert_path_to_regex(path)
                )
            )

    return documented_paths

def parse_logs(log_content: str) -> List[LogEntry]:
    """
    Parses a simple custom log format.
    Expected format per line: METHOD /path
    Example: GET /api/v1/users
    """
    logs = []
    lines = log_content.strip().split("\n")
    for line in lines:
        parts = line.strip().split()
        if len(parts) >= 2:
            method = parts[0].upper()
            path = parts[1]
            logs.append(LogEntry(method=method, path=path))
    return logs

def _assign_severity(path: str) -> Severity:
    """
    Assigns severity to a shadow endpoint based on common sensitive paths.
    """
    path_lower = path.lower()
    if any(keyword in path_lower for keyword in ["/admin", "/debug", "/shell", "/system"]):
        return Severity.CRITICAL
    if any(keyword in path_lower for keyword in ["/config", "/env", "/metrics", "/actuator", "/internal"]):
        return Severity.HIGH
    if any(keyword in path_lower for keyword in ["/test", "/dev", "/staging", "/old", "/v1", "/v2"]):
        return Severity.MEDIUM
    return Severity.LOW

def analyze_endpoints(documented_paths: List[OpenAPIPath], logs: List[LogEntry]) -> AnalysisReport:
    """
    Cross-references logs against documented OpenAPI paths to find Shadow and Zombie APIs.
    """

    # Store aggregated stats
    endpoint_stats: Dict[Tuple[str, str], AnalyzedEndpoint] = {}

    # Track which documented paths have been hit
    documented_hits = { (p.path, m): False for p in documented_paths for m in p.methods }

    for log in logs:
        matched = False
        for doc_path in documented_paths:
            if re.match(doc_path.regex_pattern, log.path) and log.method in doc_path.methods:
                matched = True
                documented_hits[(doc_path.path, log.method)] = True

                key = (log.method, doc_path.path)
                if key not in endpoint_stats:
                    endpoint_stats[key] = AnalyzedEndpoint(
                        method=log.method,
                        path=doc_path.path,
                        category=EndpointCategory.DOCUMENTED,
                        matched_documented_path=doc_path.path
                    )
                endpoint_stats[key].access_count += 1
                break

        if not matched:
            # Shadow API
            key = (log.method, log.path)
            if key not in endpoint_stats:
                endpoint_stats[key] = AnalyzedEndpoint(
                    method=log.method,
                    path=log.path,
                    category=EndpointCategory.SHADOW,
                    severity=_assign_severity(log.path)
                )
            endpoint_stats[key].access_count += 1

    # Add Zombie APIs (documented but not hit)
    for (path, method), hit in documented_hits.items():
        if not hit:
            key = (method, path)
            if key not in endpoint_stats:
                endpoint_stats[key] = AnalyzedEndpoint(
                    method=method,
                    path=path,
                    category=EndpointCategory.ZOMBIE,
                    access_count=0,
                    matched_documented_path=path
                )

    # Compile results
    results = list(endpoint_stats.values())

    documented_count = sum(1 for e in results if e.category == EndpointCategory.DOCUMENTED)
    shadow_count = sum(1 for e in results if e.category == EndpointCategory.SHADOW)
    zombie_count = sum(1 for e in results if e.category == EndpointCategory.ZOMBIE)

    return AnalysisReport(
        total_logs=len(logs),
        documented_count=documented_count,
        shadow_count=shadow_count,
        zombie_count=zombie_count,
        endpoints=results
    )
