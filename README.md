# Google SecOps AI Efficiency Suite V2

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https.python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-2.0.0-green.svg)](https://fastapi.tiangolo.com/)
[![Google ADK](https://img.shields.io/badge/ADK-Google_SecOps-cyan.svg)](https://cloud.google.com/security)
[![Gemini 3.8 Flash](https://img.shields.io/badge/Model-Gemini_3.8_Flash-purple.svg)](https://deepmind.google/technologies/gemini/)

An enterprise-grade SecOps AI Efficiency Suite built on **Google Agent Development Kit (ADK)** and **Gemini 3.8 Flash**. Provides real-time UDM telemetry streams, automated incident correlation pre-merging, live FIRST EPSS risk scoring for 2026 CISA KEV findings, SOAR playbook failure diagnostics, and live threat intelligence aggregation.

---

## 🏛️ System Architecture & Core Modules

The architecture comprises 5 core SecOps modules fully integrated into a FastAPI web application and served through an interactive dark-themed SOC Console UI:

```
                  ┌─────────────────────────────────────────┐
                  │ Google SecOps AI Efficiency Suite V2 UI  │
                  └────────────────────┬────────────────────┘
                                       │
                        ┌──────────────┴──────────────┐
                        ▼                             ▼
                 FastAPI Backend              ADK Root Agent
               (app/main.py Port 8080)    (gemini-3.8-flash)
                        │                             │
    ┌───────────────────┼───────────────────┬─────────┴─────────┐
    ▼                   ▼                   ▼                   ▼
Module 1:           Module 2:           Module 3:           Module 4:
Live EPSS          UDM Entity          SOAR Playbook       Live UDM
Prioritization     Pre-Merging          Diagnostics         Telemetry
(app/tools/         (app/tools/         (app/tools/         (app/telemetry/
 vuln_prio.py)       inc_corr.py)        soar_diag.py)       live_stream.py)
    │                   │                   │                   │
    └───────────────────┼───────────────────┴───────────────────┘
                        ▼
                    Module 5:
               Live Threat Intel
             (app/tools/threat_intel.py)
             (CISA KEV / GBHackers / THN)
```

### Module Breakdown
1. **Live FIRST EPSS Vulnerability Prioritization (`app/tools/vuln_prioritization.py`)**
   - Fetches live EPSS probabilities from official FIRST API (`https://api.first.org/data/v1/epss`).
   - Maps 2026 CISA KEV findings directly to enterprise assets (`gke-prod-frontend-pool`, `bastion-jump-host`, `prod-db-cluster-01`).
   - Computes composite operational risk scores combining CVSS, EPSS probability, internet exposure, and asset criticality.

2. **Entity Overlap Incident Correlation & Pre-Merging (`app/tools/incident_correlation.py`)**
   - Deterministically calculates shared IP, Host, and User entity overlaps across high-frequency SecOps alerts.
   - Generates parent-child pre-merge recommendations to consolidate SOC incident graphs.

3. **SOAR Playbook Execution Diagnostics (`app/tools/soar_diagnostics.py`)**
   - Evaluates failed SOAR execution logs (e.g. `403 PERMISSION_DENIED`, missing IAM roles).
   - Recommends automated code fixes and Cloud IAM policy bindings.

4. **Continuous Live UDM Telemetry Stream (`app/telemetry/live_stream.py`)**
   - Background event generator producing standard Google SecOps UDM telemetry schema events (`USER_LOGIN`, `PROCESS_EXECUTION`, `NETWORK_CONNECTION`, `SECURITY_ALERT`) every 15 seconds in memory.

5. **Live Threat Intelligence & Daily CVE Aggregator (`app/tools/threat_intel.py`)**
   - Fetches daily disclosed CISA Known Exploited Vulnerabilities catalog.
   - Aggregates live security advisories from CISA, GBHackers, and The Hacker News with background 60s cache refresh.

---

## 📁 Repository Structure

```
secops-efficiency-suite-v2/
├── agent.py                       # ADK Agent definition entrypoint
├── pyproject.toml                 # uv / setuptools build configuration
├── requirements.txt               # Dependencies (google-adk, fastapi, uvicorn, httpx)
├── app/
│   ├── agent.py                   # ADK Root Agent initialized with gemini-3.8-flash
│   ├── main.py                    # FastAPI server & REST API endpoints
│   ├── telemetry/
│   │   ├── __init__.py
│   │   └── live_stream.py         # Background UDM telemetry stream generator
│   └── tools/
│       ├── __init__.py
│       ├── incident_correlation.py# Entity overlap pre-merging logic
│       ├── soar_diagnostics.py    # SOAR failure diagnostic engine
│       ├── threat_intel.py        # Live CISA KEV & threat news feed aggregator
│       └── vuln_prioritization.py # Live FIRST EPSS API vulnerability prioritizer
└── frontend/
    └── static/
        └── index.html             # 6-Tab Dark-Themed SOC Console UI
```

---

## ⚡ Quick Start & Installation

### 1. Prerequisites
- Python 3.11 or higher
- `uv` package manager (recommended) or `pip`

### 2. Environment Setup
```bash
# Clone or navigate to the project directory
cd secops-efficiency-suite-v2

# Create and activate virtual environment
uv venv .venv
source .venv/bin/activate

# Install dependencies
uv pip install -r requirements.txt
```

### 3. Running the Application
```bash
# Start Uvicorn web server on port 8080
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

Open `http://localhost:8080/` in your browser to access the interactive **Google SecOps AI Efficiency Suite V2** console.

---

## 🔌 API Reference Endpoints

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `GET /` | `GET` | Serves the 6-Tab Dark-Themed SOC Console UI |
| `POST /api/v2/query` | `POST` | Processes natural language SecOps queries via Gemini 3.8 Flash |
| `GET /api/v2/dashboard/alerts` | `GET` | Returns 100+ realistic security alerts covering MITRE ATT&CK |
| `GET /api/v2/dashboard/detections` | `GET` | Returns 35 YARA-L detection rules with spike & noise metrics |
| `GET /api/v2/dashboard/vulnerabilities` | `GET` | Returns 2026 CISA KEV vulnerabilities with live EPSS scores |
| `GET /api/v2/dashboard/telemetry` | `GET` | Returns auto-updating UDM telemetry stream events |
| `GET /api/v2/dashboard/threat_intel` | `GET` | Returns daily CISA KEV catalog and security news advisories |

---

## 🛡️ License

Copyright 2026 Google LLC. Released under Apache License 2.0.
