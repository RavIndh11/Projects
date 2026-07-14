from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver
from state import AgentState
from agents import recon_agent, enumeration_agent, vulnerability_agent
from agents_p2 import red_teaming_agent, reporting_agent

# Initialize Graph
workflow = StateGraph(AgentState)

# Add Nodes
workflow.add_node("recon", recon_agent)
workflow.add_node("enumerate", enumeration_agent)
workflow.add_node("vuln_analysis", vulnerability_agent)
workflow.add_node("red_teaming", red_teaming_agent)
workflow.add_node("reporting", reporting_agent)

# Add Edges (Linear flow for this VAPT scenario)
workflow.add_edge(START, "recon")
workflow.add_edge("recon", "enumerate")
workflow.add_edge("enumerate", "vuln_analysis")
workflow.add_edge("vuln_analysis", "red_teaming")
workflow.add_edge("red_teaming", "reporting")
workflow.add_edge("reporting", END)

# Set up Human-in-the-loop Memory (Checkpointer)
memory = MemorySaver()

# Compile Graph with an interrupt BEFORE the red_teaming node
# This stops execution and waits for human approval
ares_graph = workflow.compile(
    checkpointer=memory,
    interrupt_before=["red_teaming"]
)
