from typing import TypedDict, Annotated, List, Dict, Any
from langgraph.graph.message import add_messages

class Vulnerability(TypedDict):
    service: str
    description: str
    severity: str
    cve: str

class AttackPlan(TypedDict):
    target: str
    vulnerability_id: str
    description: str
    proposed_payload: str
    approved: bool

class AgentState(TypedDict):
    # LangGraph State
    messages: Annotated[list, add_messages]
    target_ip: str
    discovered_ports: List[int]
    services: Dict[str, str] # e.g., {"80": "Apache 2.4.49"}
    vulnerabilities: List[Vulnerability]
    attack_plans: List[AttackPlan]
    execution_results: List[str]
    report: str
