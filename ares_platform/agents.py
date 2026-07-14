from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from state import AgentState
from tools import scan_ports, enumerate_services, search_vulnerability_database
import os
from dotenv import load_dotenv

load_dotenv()

# We use a fast, reliable model for the agents
# You can replace this with Ollama if you want local execution
llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0)

def recon_agent(state: AgentState):
    """Runs port scanning on the target."""
    target = state.get("target_ip")
    print(f"[*] Recon Agent: Scanning {target}...")

    # We directly use the tool for deterministic flow, though we could let the LLM call it
    result = scan_ports.invoke({"target_ip": target})

    return {"discovered_ports": result["open_ports"], "messages": [AIMessage(content=f"Recon Agent discovered open ports: {result['open_ports']}")]}

def enumeration_agent(state: AgentState):
    """Enumerates services on the discovered ports."""
    target = state.get("target_ip")
    ports = state.get("discovered_ports", [])
    print(f"[*] Enumeration Agent: Inspecting ports {ports}...")

    if not ports:
        return {"messages": [AIMessage(content="Enumeration Agent: No ports to enumerate.")]}

    result = enumerate_services.invoke({"target_ip": target, "ports": ports})

    return {"services": result, "messages": [AIMessage(content=f"Enumeration Agent identified services: {result}")]}

def vulnerability_agent(state: AgentState):
    """Analyzes services and proposes attack plans."""
    services = state.get("services", {})
    print(f"[*] Vulnerability Agent: Analyzing {services}...")

    attack_plans = []
    vulnerabilities = []

    for port, service in services.items():
        # Query the RAG database
        vuln_data = search_vulnerability_database.invoke({"service_name": service})

        # Use LLM to formulate an attack plan based on RAG data
        prompt = f"""
        You are a Vulnerability Strategist.
        Target Service: {service}
        Knowledgebase Data: {vuln_data}

        If a vulnerability exists, formulate an exact proposed payload to exploit it.
        Return ONLY a string in this format: VULNERABILITY_FOUND|severity|cve|proposed_payload
        If no vulnerability is found, return NO_VULNERABILITY
        """

        response = llm.invoke([SystemMessage(content=prompt)])

        if response.content.startswith("VULNERABILITY_FOUND"):
            parts = response.content.split("|")
            if len(parts) >= 4:
                vuln = {
                    "service": service,
                    "description": f"Exploitable flaw in {service}",
                    "severity": parts[1],
                    "cve": parts[2]
                }
                plan = {
                    "target": state.get("target_ip"),
                    "vulnerability_id": parts[2],
                    "description": f"Exploit {service}",
                    "proposed_payload": parts[3],
                    "approved": False # Requires human approval
                }
                vulnerabilities.append(vuln)
                attack_plans.append(plan)

    return {
        "vulnerabilities": vulnerabilities,
        "attack_plans": attack_plans,
        "messages": [AIMessage(content=f"Vulnerability Agent generated {len(attack_plans)} attack plans.")]
    }
