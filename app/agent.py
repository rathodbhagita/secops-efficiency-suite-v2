# Copyright 2026 Google LLC
# Google SecOps AI Efficiency Suite V2 — ADK Root Agent

from google.adk.agents import Agent
from google.adk.apps import App
from google.adk.models import Gemini
from google.genai import types

from app.tools.vuln_prioritization import prioritize_vulnerabilities_v2
from app.tools.incident_correlation import correlate_incidents_v2
from app.tools.soar_diagnostics import diagnose_soar_failures_v2
from app.tools.threat_intel import get_threat_intel_summary

# Configure Gemini model to gemini-3.8-flash in us-central1
model = Gemini(
    model="gemini-3.8-flash",
    location="us-central1",
    retry_options=types.HttpRetryOptions(attempts=3),
)

root_agent = Agent(
    name="secops_efficiency_suite_v2_agent",
    model=model,
    instruction="""You are an expert AI SOC Efficiency Analyst for Google SecOps (V2).

You are equipped with specialized V2 security analysis tools:
1. `prioritize_vulnerabilities_v2(cve_ids)`: Live FIRST EPSS API integration + Security Command Center risk ranking (Internet Exposure x CVSS x Asset Criticality).
2. `correlate_incidents_v2(alert_id)`: Calculates deterministic entity overlap (IP, Host, User) across alerts to recommend incident pre-merges with confidence scores.
3. `diagnose_soar_failures_v2()`: Reads failed SOAR playbook logs and provides root cause hypotheses and preventive IAM/code fixes.
4. `get_threat_intel_summary(query)`: Live CISA KEV daily disclosed CVEs, affected software products, and security news advisories (The Hacker News, GBHackers, CISA).

Use these tools to assist SOC analysts in eliminating alert fatigue, prioritizing real operational vulnerabilities, troubleshooting SOAR automation failures, and triaging trending threat intelligence.""",
    tools=[
        prioritize_vulnerabilities_v2,
        correlate_incidents_v2,
        diagnose_soar_failures_v2,
        get_threat_intel_summary,
    ],
)

app = App(
    root_agent=root_agent,
    name="app",
)
