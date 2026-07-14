import streamlit as st
from graph import ares_graph
from database import init_db
import uuid

st.set_page_config(page_title="Ares Platform", layout="wide")

# Initialize DB on first run
@st.cache_resource
def setup_db():
    init_db()
setup_db()

st.title("Ares: Multi-Agent Red Teaming Platform")
st.markdown("Automated Recon -> Enum -> Vuln Analysis -> **[Human Approval]** -> Exploit -> Reporting")

# Session state to hold the thread ID for LangGraph memory
if "thread_id" not in st.session_state:
    st.session_state.thread_id = str(uuid.uuid4())

config = {"configurable": {"thread_id": st.session_state.thread_id}}

# Step 1: Input Target
st.sidebar.header("Target Configuration")
target_ip = st.sidebar.text_input("Target IP/Domain", value="192.168.1.100")

if st.sidebar.button("Launch Ares Agents"):
    st.session_state.started = True
    st.session_state.thread_id = str(uuid.uuid4()) # New thread for new scan
    config = {"configurable": {"thread_id": st.session_state.thread_id}}

    with st.spinner("Agents are scanning and analyzing..."):
        # Run graph up to the interrupt (before red_teaming)
        initial_state = {"target_ip": target_ip}
        for event in ares_graph.stream(initial_state, config):
            pass # We just want it to reach the interrupt

# Display Current State and HITL Checkpoint
if "started" in st.session_state:
    current_state = ares_graph.get_state(config)
    state_values = current_state.values

    # Show Agent Findings
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Discovered Services")
        if "services" in state_values:
            st.json(state_values["services"])

    with col2:
        st.subheader("Vulnerability Analysis")
        if "vulnerabilities" in state_values:
            for v in state_values["vulnerabilities"]:
                st.warning(f"**{v['cve']}** ({v['severity']}): {v['service']} - {v['description']}")

    st.divider()

    # Check if we are waiting for human approval
    if current_state.next and "red_teaming" in current_state.next:
        st.error("🛑 Graph Execution Paused: Awaiting Human Approval")

        attack_plans = state_values.get("attack_plans", [])
        if not attack_plans:
            st.info("No exploitable vulnerabilities found. You can resume to generate the report.")
            if st.button("Resume (Generate Report)"):
                for event in ares_graph.stream(None, config):
                    pass
                st.rerun()
        else:
            st.markdown("### Proposed Attack Plans (Review Required)")

            # Create a form to approve/deny plans
            with st.form("approval_form"):
                approved_plans = []
                for i, plan in enumerate(attack_plans):
                    st.markdown(f"**Target:** {plan['target']} | **Vulnerability:** {plan['vulnerability_id']}")
                    st.code(plan['proposed_payload'], language="bash")
                    approve = st.checkbox(f"Approve Execution of {plan['vulnerability_id']}", key=f"app_{i}")

                    # Update plan based on checkbox
                    plan["approved"] = approve
                    approved_plans.append(plan)

                submitted = st.form_submit_button("Submit Approvals & Resume Attack")

                if submitted:
                    # Update state with approved plans
                    ares_graph.update_state(config, {"attack_plans": approved_plans})

                    # Resume graph execution
                    with st.spinner("Red Teaming Agent is executing..."):
                        for event in ares_graph.stream(None, config):
                            pass
                    st.rerun()

    # If the graph has finished (no 'next' node)
    elif not current_state.next and "report" in state_values:
        st.success("✅ Assessment Complete")
        st.markdown("### Final Report")
        st.markdown(state_values["report"])

        # Optionally allow download
        st.download_button(
            label="Download Markdown Report",
            data=state_values["report"],
            file_name=f"VAPT_Report_{target_ip}.md",
            mime="text/markdown"
        )
