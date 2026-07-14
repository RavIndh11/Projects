from state import AgentState
from tools import execute_exploit
from langchain_core.messages import AIMessage

def red_teaming_agent(state: AgentState):
    """Executes ONLY the attack plans that have been approved by a human."""
    attack_plans = state.get("attack_plans", [])
    results = []

    print(f"[*] Red Teaming Agent: Checking {len(attack_plans)} plans for approval...")

    for plan in attack_plans:
        if plan.get("approved"):
            print(f"    -> EXECUTING APPROVED PLAN: {plan['vulnerability_id']}")
            # Changed to generate PoC script instead of direct execution
            output = execute_exploit.invoke({
                "target_ip": plan['target'],
                "vulnerability_id": plan['vulnerability_id'],
                "payload_details": plan['proposed_payload']
            })
            results.append(f"Execution of {plan['vulnerability_id']}: {output}")
        else:
            print(f"    -> SKIPPED (Not Approved): {plan['vulnerability_id']}")
            results.append(f"Skipped {plan['vulnerability_id']} (Unapproved)")

    return {
        "execution_results": results,
        "messages": [AIMessage(content=f"Red Teaming Agent execution finished: {results}")]
    }

def reporting_agent(state: AgentState):
    """Generates the final VAPT report."""
    target = state.get("target_ip")
    vulnerabilities = state.get("vulnerabilities", [])
    results = state.get("execution_results", [])

    report = f"# VAPT Report for {target}\n\n"

    report += "## Executive Summary\n"
    report += f"The Ares platform conducted an automated vulnerability assessment on {target}. "
    report += f"{len(vulnerabilities)} potential vulnerabilities were identified.\n\n"

    report += "## Discovered Vulnerabilities\n"
    for v in vulnerabilities:
        report += f"- **{v['service']}**: {v['description']} ({v['cve']}, Severity: {v['severity']})\n"

    report += "\n## Exploitation Results\n"
    for r in results:
        report += f"- {r}\n"

    print(f"[*] Reporting Agent: Final report generated.")
    return {"report": report}
