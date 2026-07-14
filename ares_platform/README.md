# Ares: Multi-Agent Red Teaming Platform

Ares is an automated Vulnerability Assessment and Penetration Testing (VAPT) platform powered by LangGraph. It uses a swarm of specialized AI agents to scan, enumerate, and analyze targets. Crucially, it incorporates a **Human-In-The-Loop (HITL)** architecture, pausing execution before exploiting any vulnerabilities to wait for human approval via a Streamlit UI.

## Architecture & Agents
1. **Recon Agent:** Broad discovery (nmap).
2. **Enumeration Agent:** Deep inspection of services.
3. **Vulnerability Agent:** Queries a local ChromaDB (Vector DB) filled with CVEs and proposes attack plans.
4. **[HITL PAUSE]**
5. **Red Teaming Agent:** Executes approved exploits.
6. **Reporting Agent:** Generates a comprehensive Markdown report.

## Setup
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Set your OpenAI API key in a `.env` file:
   ```env
   OPENAI_API_KEY=your-api-key
   ```
   *(Note: The code is designed to use GPT-3.5-turbo via LangChain. You can swap `ChatOpenAI` for a local Ollama instance in `agents.py` if desired).*

3. Run the Streamlit UI:
   ```bash
   streamlit run ui.py
   ```

## Workflow
1. Open the UI and enter a Target IP.
2. Click **Launch Ares Agents**. The first three agents will run and gather data.
3. Review the proposed attack payloads in the UI.
4. Check the boxes for the exploits you approve, then click **Submit Approvals & Resume Attack**.
5. The Red Teaming Agent will execute the approved payloads, and the Reporting Agent will generate a downloadable Markdown report.
