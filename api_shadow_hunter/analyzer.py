import yaml
import json
import re
from typing import Set, Tuple
from schemas import APIEndpoint, AnalysisResult

class SpecParser:
    @staticmethod
    def parse(spec_content: str) -> Set[Tuple[str, str]]:
        """Parses an OpenAPI spec (YAML/JSON) to extract documented endpoints."""
        endpoints = set()
        try:
            # Try YAML parsing (which also parses JSON)
            spec = yaml.safe_load(spec_content)
        except yaml.YAMLError:
            return endpoints

        if not spec or 'paths' not in spec:
            return endpoints

        for path, path_item in spec['paths'].items():
            if isinstance(path_item, dict):
                for method in path_item.keys():
                    if method.lower() in ['get', 'post', 'put', 'delete', 'patch', 'options', 'head']:
                        # Normalize path by converting path parameters like {id} to a regex pattern or generic token
                        # For simplicity in this analyzer, we will replace path parameters with {param}
                        normalized_path = re.sub(r'\{[^}]+\}', '{param}', path)
                        endpoints.add((method.upper(), normalized_path))

        return endpoints

class LogParser:
    @staticmethod
    def _normalize_path(path: str) -> str:
        """Heuristically normalize log paths to match spec paths (e.g., replace IDs with {param})."""
        # Very basic heuristic: replace UUIDs or digit-only segments with {param}
        path = re.sub(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(/|$)', '/{param}\\1', path)
        path = re.sub(r'/\d+(/|$)', '/{param}\\1', path)
        return path

    @staticmethod
    def parse(log_content: str) -> Set[Tuple[str, str]]:
        """Parses access logs to extract accessed endpoints."""
        endpoints = set()
        for line in log_content.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                # Try parsing as JSON (common for structured logs)
                log_entry = json.loads(line)
                method = log_entry.get('method') or log_entry.get('http_method')
                path = log_entry.get('path') or log_entry.get('request_path')

                if method and path and isinstance(method, str) and isinstance(path, str):
                    # Strip query strings
                    path = path.split('?')[0]
                    normalized_path = LogParser._normalize_path(path)
                    endpoints.add((method.upper(), normalized_path))
            except json.JSONDecodeError:
                # Fallback to basic text parsing (assuming combined log format or similar)
                # Look for "METHOD /path HTTP/1.1"
                match = re.search(r'"(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+([^?\s]+)[^"]*"', line, re.IGNORECASE)
                if match:
                    method = match.group(1).upper()
                    path = match.group(2)
                    normalized_path = LogParser._normalize_path(path)
                    endpoints.add((method, normalized_path))

        return endpoints

class APIAnalyzer:
    @staticmethod
    def analyze(spec_content: str, log_content: str) -> AnalysisResult:
        """Compares documented API endpoints against access logs."""
        documented_endpoints = SpecParser.parse(spec_content)
        accessed_endpoints = LogParser.parse(log_content)

        shadow_apis_set = accessed_endpoints - documented_endpoints
        zombie_apis_set = documented_endpoints - accessed_endpoints

        shadow_apis = [APIEndpoint(method=m, path=p) for m, p in sorted(list(shadow_apis_set))]
        zombie_apis = [APIEndpoint(method=m, path=p) for m, p in sorted(list(zombie_apis_set))]

        return AnalysisResult(
            total_documented=len(documented_endpoints),
            total_accessed=len(accessed_endpoints),
            shadow_apis=shadow_apis,
            zombie_apis=zombie_apis
        )
