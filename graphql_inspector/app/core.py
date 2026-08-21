import httpx
import logging
from typing import Dict, Any, Tuple
from app.models import AnalyzeRequest, AnalyzeResponse, ThreatSeverity

logger = logging.getLogger(__name__)

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
        }
      }
    }
    mutationType {
      name
    }
  }
}
"""

SENSITIVE_KEYWORDS = [
    "password", "pwd", "token", "secret", "key", "auth", "credential",
    "ssn", "creditcard", "bank", "apikey", "session", "oauth"
]

async def fetch_schema(url: str, headers: Dict[str, str] = None) -> Tuple[bool, Dict[str, Any], str]:
    """
    Sends an introspection query to the given URL and returns the parsed schema.
    Returns (introspection_enabled, schema_data, error_message).
    """
    if headers is None:
        headers = {}

    # Ensure Content-Type is set for GraphQL queries over HTTP
    if "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.post(
                url,
                json={"query": INTROSPECTION_QUERY},
                headers=headers
            )
            response.raise_for_status()
            data = response.json()

            # Check if it looks like a valid introspection response
            if "data" in data and "__schema" in data["data"] and data["data"]["__schema"] is not None:
                return True, data["data"]["__schema"], None
            elif "errors" in data:
                return False, {}, "Introspection is likely disabled (GraphQL errors returned)."
            else:
                 return False, {}, "Unexpected response format."

    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error checking {url}: {e}")
        return False, {}, f"HTTP Error: {e.response.status_code}"
    except Exception as e:
        logger.error(f"Error checking {url}: {e}")
        return False, {}, str(e)

def extract_mutations(schema: Dict[str, Any]) -> list[str]:
    """Extracts available mutations from the schema."""
    mutations = []
    try:
        mutation_type_name = schema.get("mutationType", {}).get("name")
        if mutation_type_name:
            # Find the type matching the mutation type name
            for t in schema.get("types", []):
                if t.get("name") == mutation_type_name:
                    for field in t.get("fields", []):
                        if field and field.get("name"):
                            mutations.append(field.get("name"))
                    break
    except Exception as e:
        logger.error(f"Error extracting mutations: {e}")
    return mutations

def extract_sensitive_fields(schema: Dict[str, Any]) -> list[str]:
    """Searches the schema for fields matching sensitive keywords."""
    sensitive_fields = set()
    try:
        for t in schema.get("types", []):
            type_name = t.get("name", "")
            # Ignore built-in GraphQL types
            if type_name.startswith("__"):
                continue

            for field in t.get("fields") or []:
                field_name = field.get("name", "")

                # Check field name against keywords
                for keyword in SENSITIVE_KEYWORDS:
                    if keyword.lower() in field_name.lower():
                        sensitive_fields.add(f"{type_name}.{field_name}")
                        break
    except Exception as e:
         logger.error(f"Error extracting sensitive fields: {e}")

    return list(sensitive_fields)

def calculate_severity(introspection_enabled: bool, sensitive_fields: list, mutations: list) -> str:
    """Calculates threat severity based on findings."""
    if not introspection_enabled:
        return ThreatSeverity.LOW

    if len(sensitive_fields) > 0 and len(mutations) > 0:
        return ThreatSeverity.CRITICAL
    elif len(sensitive_fields) > 0:
        return ThreatSeverity.HIGH
    elif len(mutations) > 0:
        return ThreatSeverity.MEDIUM
    else:
        return ThreatSeverity.LOW

async def analyze_graphql_endpoint(request: AnalyzeRequest) -> AnalyzeResponse:
    """Orchestrates the analysis of a GraphQL endpoint."""
    url_str = str(request.url)

    introspection_enabled, schema, error = await fetch_schema(url_str, request.headers)

    if not introspection_enabled:
        return AnalyzeResponse(
            url=url_str,
            introspection_enabled=False,
            severity=ThreatSeverity.LOW,
            error=error
        )

    sensitive_fields = extract_sensitive_fields(schema)
    mutations = extract_mutations(schema)
    severity = calculate_severity(introspection_enabled, sensitive_fields, mutations)

    return AnalyzeResponse(
        url=url_str,
        introspection_enabled=True,
        sensitive_fields=sensitive_fields,
        mutations=mutations,
        severity=severity
    )
