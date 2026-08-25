import httpx
import logging
from typing import List, Dict, Any
from .models import ScanResult, Vulnerability

logger = logging.getLogger(__name__)

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}
"""

SENSITIVE_KEYWORDS = ["password", "token", "secret", "ssn", "email", "credential", "key", "auth"]

async def run_scan(url: str) -> ScanResult:
    result = ScanResult(
        url=url,
        introspection_enabled=False,
        sensitive_fields_found=[],
        vulnerabilities=[],
        status="scanning"
    )

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                url,
                json={"query": INTROSPECTION_QUERY},
                headers={"Content-Type": "application/json"}
            )

            if response.status_code == 200:
                data = response.json()
                if "data" in data and "__schema" in data["data"]:
                    result.introspection_enabled = True
                    result.vulnerabilities.append(
                        Vulnerability(
                            title="GraphQL Introspection Enabled",
                            severity="High",
                            description="The GraphQL endpoint has introspection enabled, which reveals the entire schema."
                        )
                    )

                    # Analyze schema for sensitive fields
                    schema = data["data"]["__schema"]
                    for type_info in schema.get("types", []):
                        # Filter out internal GraphQL types
                        if type_info.get("name", "").startswith("__"):
                            continue

                        fields = type_info.get("fields")
                        if fields:
                            for field in fields:
                                field_name = field.get("name", "").lower()
                                for keyword in SENSITIVE_KEYWORDS:
                                    if keyword in field_name:
                                        result.sensitive_fields_found.append(f"{type_info.get('name')}.{field.get('name')}")
                                        break # avoid duplicates for this field

                    if result.sensitive_fields_found:
                        result.vulnerabilities.append(
                            Vulnerability(
                                title="Sensitive Fields Exposed",
                                severity="Critical",
                                description=f"Found fields with sensitive names: {', '.join(result.sensitive_fields_found)}"
                            )
                        )

            result.status = "completed"

    except Exception as e:
        logger.error(f"Error scanning {url}: {e}")
        result.status = "failed"
        result.error_message = str(e)

    return result
