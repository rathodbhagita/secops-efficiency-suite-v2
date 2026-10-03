# Copyright 2026 Google LLC
# Google SecOps AI Efficiency Suite V2 - Enterprise FastAPI Application

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Dict, Optional, List
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.agent import root_agent
from app.tools.vuln_prioritization import prioritize_vulnerabilities_v2, MOCK_SCC_FINDINGS_2026, fetch_epss_scores
from app.tools.incident_correlation import correlate_incidents_v2, SAMPLE_ALERT_DATABASE
from app.tools.soar_diagnostics import diagnose_soar_failures_v2
from app.tools.threat_intel import get_threat_intel_summary, get_cached_threat_intel, refresh_threat_intel_cache_loop
from app.telemetry.live_stream import start_telemetry_stream, get_recent_udm_events

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing Google SecOps AI Efficiency Suite V2 Server...")
    telemetry_task = asyncio.create_task(start_telemetry_stream())
    intel_task = asyncio.create_task(refresh_threat_intel_cache_loop())
    yield
    telemetry_task.cancel()
    intel_task.cancel()
    logger.info("SecOps V2 background tasks shutdown cleanly.")


app = FastAPI(
    title="Google SecOps AI Efficiency Suite V2",
    version="2.0.0",
    description="Enterprise SOC Efficiency Platform powered by Gemini 3.8 Flash & Real-Time UDM Streams",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class QueryRequest(BaseModel):
    prompt: str


class QueryResponse(BaseModel):
    status: str
    prompt: str
    result: str


def generate_enterprise_100_alerts() -> List[Dict]:
    """Generates 100+ realistic enterprise security alerts covering MITRE ATT&CK tactics."""
    base_templates = [
        ("Credential Access", "RULE-CRED-SPRAY", "AD Password Spraying Attack Detected", "HIGH", "198.51.100.42", "prod-dc-01", "j_smith"),
        ("Credential Access", "RULE-LSASS-DUMP", "LSASS Process Memory Dump via Taskmgr", "CRITICAL", "198.51.100.42", "prod-db-cluster-01", "admin_root"),
        ("Credential Access", "RULE-KERBEROAST", "Kerberoasting TGS Ticket Request Burst", "HIGH", "10.0.12.88", "corp-ad-02", "svc_backup"),
        ("Lateral Movement", "RULE-PTH-ATTACK", "Pass-the-Hash Authentication Attempt", "CRITICAL", "198.51.100.42", "prod-db-cluster-01", "admin_root"),
        ("Lateral Movement", "RULE-PSEXEC-SPAWN", "Remote PsExec Execution on Host", "HIGH", "198.51.100.55", "app-srv-14", "local_admin"),
        ("Lateral Movement", "RULE-WMI-REMOTE", "WMI Remote Process Execution Spawned", "MEDIUM", "10.0.14.10", "web-fe-01", "deploy_bot"),
        ("Persistence", "RULE-CRON-MOD", "Suspicious Linux Cron Job Modification", "MEDIUM", "192.168.1.105", "prod-api-gw", "www-data"),
        ("Persistence", "RULE-SCHTASK-NEW", "Unusual Scheduled Task Registered", "MEDIUM", "10.0.4.19", "workstation-88", "m_johnson"),
        ("Privilege Escalation", "RULE-PRIV-ESC", "Unusual Sudo Privilege Escalation", "HIGH", "198.51.100.42", "prod-db-cluster-01", "admin_root"),
        ("Privilege Escalation", "RULE-GCP-IAM-BIND", "GCP IAM Role Binding Owner Privilege Added", "CRITICAL", "35.232.10.4", "gcp-proj-prod", "ci_deployer"),
        ("Command & Control", "RULE-COBALT-BEACON", "Cobalt Strike Malleable C2 Beacon Traffic", "CRITICAL", "198.51.100.42", "prod-db-cluster-01", "svc_export"),
        ("Command & Control", "RULE-DNS-TUNNEL", "DNS Exfiltration & Tunneling Pattern", "HIGH", "10.0.8.22", "user-laptop-44", "a_davis"),
        ("Exfiltration", "RULE-DATA-EGRESS", "Asymmetrical Outbound Data Egress (120GB)", "HIGH", "198.51.100.42", "prod-db-cluster-01", "svc_export"),
        ("Defense Evasion", "RULE-PS-ENCODED", "PowerShell Base64 Encoded Script Execution", "HIGH", "10.0.2.14", "finance-pc-02", "r_taylor"),
        ("Defense Evasion", "RULE-LOG-CLEAR", "Audit Security Event Log Cleared (wevtutil)", "HIGH", "10.0.5.99", "prod-dc-01", "domain_admin")
    ]
    
    alerts = []
    primary_parent = "ALT-1001"
    
    for i in range(1, 106):
        aid = f"ALT-{1000 + i}"
        tpl = base_templates[(i - 1) % len(base_templates)]
        tactic, rule_id, alert_name, base_prio, src_ip, dst_host, dst_user = tpl
        
        if i % 7 == 0:
            prio = "CRITICAL"
        elif i % 5 == 0:
            prio = "HIGH"
        elif i % 3 == 0:
            prio = "MEDIUM"
        else:
            prio = "LOW"
            
        is_premerge = (src_ip == "198.51.100.42" or dst_host == "prod-db-cluster-01" or i % 3 == 0) and (aid != primary_parent)
        
        alerts.append({
            "alert_id": aid,
            "rule_id": rule_id,
            "tactic": tactic,
            "alert_name": f"{alert_name} #{i}",
            "source_ip": src_ip if i % 2 == 0 else f"198.51.100.{(i % 50) + 1}",
            "target_host": dst_host if i % 3 == 0 else f"prod-node-{(i % 20) + 1}",
            "target_user": dst_user if i % 2 == 0 else f"user_{(i % 15) + 1}",
            "priority": prio,
            "status": "OPEN" if i % 4 != 0 else "IN_TRIAGE",
            "premerge_candidacy": is_premerge,
            "recommended_parent": primary_parent if is_premerge else None,
            "timestamp": f"2026-10-03T{10 + (i % 8):02d}:{(i % 60):02d}:00Z"
        })
        
    return alerts


ENTERPRISE_35_DETECTION_RULES = [
    {"rule_id": "RULE-2026-001", "rule_name": "PowerShell Encoded Command Execution", "alert_spike_count_24h": 412, "noise_ratio": "42.1%", "top_offender_ip": "10.0.2.14", "top_user": "r_taylor", "tuning_status": "EXCLUSION_RECOMMENDED", "recommended_yara_rule": "exclude_signed_sccm_scripts"},
    {"rule_id": "RULE-2026-002", "rule_name": "Suspicious Service Creation (sc.exe)", "alert_spike_count_24h": 85, "noise_ratio": "18.4%", "top_offender_ip": "10.0.4.19", "top_user": "m_johnson", "tuning_status": "ACTIVE_TRIAGE", "recommended_yara_rule": None},
    {"rule_id": "RULE-2026-003", "rule_name": "Rare Inbound SSH Connection from External Range", "alert_spike_count_24h": 1450, "noise_ratio": "83.4%", "top_offender_ip": "10.0.4.15", "top_user": "svc_scanner", "tuning_status": "EXCLUSION_RECOMMENDED", "recommended_yara_rule": "exclude_internal_vulnerability_scanner"},
    {"rule_id": "RULE-2026-004", "rule_name": "Mimikatz Process Memory Dump Attempt", "alert_spike_count_24h": 8, "noise_ratio": "0.0%", "top_offender_ip": "198.51.100.42", "top_user": "admin_root", "tuning_status": "CRITICAL_ALERT", "recommended_yara_rule": None},
    {"rule_id": "RULE-2026-005", "rule_name": "Unusual GCP Service Account Creation", "alert_spike_count_24h": 29, "noise_ratio": "12.0%", "top_offender_ip": "35.232.10.4", "top_user": "terraform-sa", "tuning_status": "TUNING_REVIEW", "recommended_yara_rule": "filter_automated_ci_cd_provisioner"},
    {"rule_id": "RULE-2026-006", "rule_name": "LSASS Memory Dump via Task Manager", "alert_spike_count_24h": 3, "noise_ratio": "0.0%", "top_offender_ip": "198.51.100.42", "top_user": "admin_root", "tuning_status": "CRITICAL_ALERT", "recommended_yara_rule": None},
    {"rule_id": "RULE-2026-007", "rule_name": "Pass-the-Hash Attack Pattern", "alert_spike_count_24h": 14, "noise_ratio": "7.1%", "top_offender_ip": "198.51.100.42", "top_user": "admin_root", "tuning_status": "CRITICAL_ALERT", "recommended_yara_rule": None},
    {"rule_id": "RULE-2026-008", "rule_name": "Kerberoasting TGS Ticket Request Spike", "alert_spike_count_24h": 68, "noise_ratio": "25.0%", "top_offender_ip": "10.0.12.88", "top_user": "svc_backup", "tuning_status": "TUNING_REVIEW", "recommended_yara_rule": "exclude_legitimate_kerberos_delegation"},
    {"rule_id": "RULE-2026-009", "rule_name": "DNS Tunneling and Data Exfiltration Pattern", "alert_spike_count_24h": 180, "noise_ratio": "33.3%", "top_offender_ip": "10.0.8.22", "top_user": "a_davis", "tuning_status": "ACTIVE_TRIAGE", "recommended_yara_rule": None},
    {"rule_id": "RULE-2026-010", "rule_name": "Cobalt Strike Malleable C2 Beacon", "alert_spike_count_24h": 6, "noise_ratio": "0.0%", "top_offender_ip": "198.51.100.42", "top_user": "svc_export", "tuning_status": "CRITICAL_ALERT", "recommended_yara_rule": None},
    {"rule_id": "RULE-2026-011", "rule_name": "AWS S3 Bucket Made Publicly Accessible", "alert_spike_count_24h": 19, "noise_ratio": "10.5%", "top_offender_ip": "54.210.8.99", "top_user": "cloud_admin", "tuning_status": "EXCLUSION_RECOMMENDED", "recommended_yara_rule": "exclude_public_static_assets_bucket"},
    {"rule_id": "RULE-2026-012", "rule_name": "GCP IAM Security Policy Modified", "alert_spike_count_24h": 45, "noise_ratio": "15.5%", "top_offender_ip": "35.232.10.4", "top_user": "sec_auditor", "tuning_status": "TUNING_REVIEW", "recommended_yara_rule": None},
    {"rule_id": "RULE-2026-013", "rule_name": "Suspicious Scheduled Task Creation (schtasks)", "alert_spike_count_24h": 94, "noise_ratio": "22.3%", "top_offender_ip": "10.0.4.19", "top_user": "m_johnson", "tuning_status": "ACTIVE_TRIAGE", "recommended_yara_rule": None},
    {"rule_id": "RULE-2026-014", "rule_name": "Sudo Command Execution by Non-Admin User", "alert_spike_count_24h": 310, "noise_ratio": "64.5%", "top_offender_ip": "192.168.1.105", "top_user": "dev_user01", "tuning_status": "EXCLUSION_RECOMMENDED", "recommended_yara_rule": "exclude_developer_bastion_sudoers"},
    {"rule_id": "RULE-2026-015", "rule_name": "Linux Cron Job Modification", "alert_spike_count_24h": 52, "noise_ratio": "11.5%", "top_offender_ip": "192.168.1.105", "top_user": "www-data", "tuning_status": "ACTIVE_TRIAGE", "recommended_yara_rule": None},
    {"rule_id": "RULE-2026-016", "rule_name": "Asymmetrical Cloud Storage Export (>50GB)", "alert_spike_count_24h": 15, "noise_ratio": "6.6%", "top_offender_ip": "198.51.100.42", "top_user": "svc_export", "tuning_status": "CRITICAL_ALERT", "recommended_yara_rule": None},
    {"rule_id": "RULE-2026-017", "rule_name": "Web Shell Command Execution in Apache/Nginx", "alert_spike_count_24h": 9, "noise_ratio": "0.0%", "top_offender_ip": "203.0.113.88", "top_user": "www-data", "tuning_status": "CRITICAL_ALERT", "recommended_yara_rule": None},
    {"rule_id": "RULE-2026-018", "rule_name": "Tor Exit Node Inbound Traffic Detected", "alert_spike_count_24h": 88, "noise_ratio": "45.0%", "top_offender_ip": "185.220.101.5", "top_user": "anonymous", "tuning_status": "ACTIVE_TRIAGE", "recommended_yara_rule": None},
    {"rule_id": "RULE-2026-019", "rule_name": "Port Scan Activity Against Internal Network", "alert_spike_count_24h": 620, "noise_ratio": "78.2%", "top_offender_ip": "10.0.4.15", "top_user": "sec_scanner_agent", "tuning_status": "EXCLUSION_RECOMMENDED", "recommended_yara_rule": "exclude_qualys_scanner_range"},
    {"rule_id": "RULE-2026-020", "rule_name": "Multiple Failed Root SSH Logins", "alert_spike_count_24h": 2400, "noise_ratio": "91.2%", "top_offender_ip": "198.51.100.42", "top_user": "root", "tuning_status": "EXCLUSION_RECOMMENDED", "recommended_yara_rule": "exclude_fail2ban_auto_blocked"},
    {"rule_id": "RULE-2026-021", "rule_name": "Unsigned Binary Executed from Temp Directory", "alert_spike_count_24h": 140, "noise_ratio": "38.5%", "top_offender_ip": "10.0.3.44", "top_user": "k_wilson", "tuning_status": "ACTIVE_TRIAGE", "recommended_yara_rule": None},
    {"rule_id": "RULE-2026-022", "rule_name": "Password Spray Attack Across Active Directory", "alert_spike_count_24h": 890, "noise_ratio": "55.0%", "top_offender_ip": "198.51.100.42", "top_user": "multiple_users", "tuning_status": "TUNING_REVIEW", "recommended_yara_rule": "filter_known_vpn_gateway_retry"},
    {"rule_id": "RULE-2026-023", "rule_name": "Suspicious WMI Remote Process Spawn", "alert_spike_count_24h": 33, "noise_ratio": "9.1%", "top_offender_ip": "10.0.14.10", "top_user": "deploy_bot", "tuning_status": "ACTIVE_TRIAGE", "recommended_yara_rule": None},
    {"rule_id": "RULE-2026-024", "rule_name": "PsExec Execution on Domain Controller", "alert_spike_count_24h": 11, "noise_ratio": "0.0%", "top_offender_ip": "198.51.100.55", "top_user": "local_admin", "tuning_status": "CRITICAL_ALERT", "recommended_yara_rule": None},
    {"rule_id": "RULE-2026-025", "rule_name": "Audit Security Event Log Cleared (wevtutil)", "alert_spike_count_24h": 5, "noise_ratio": "0.0%", "top_offender_ip": "10.0.5.99", "top_user": "domain_admin", "tuning_status": "CRITICAL_ALERT", "recommended_yara_rule": None},
    {"rule_id": "RULE-2026-026", "rule_name": "GCP Cloud Audit Logs Disabled", "alert_spike_count_24h": 2, "noise_ratio": "0.0%", "top_offender_ip": "35.232.10.4", "top_user": "owner_account@corp.com", "tuning_status": "CRITICAL_ALERT", "recommended_yara_rule": None},
    {"rule_id": "RULE-2026-027", "rule_name": "Windows Token Elevation Attempt", "alert_spike_count_24h": 17, "noise_ratio": "5.8%", "top_offender_ip": "10.0.2.14", "top_user": "r_taylor", "tuning_status": "ACTIVE_TRIAGE", "recommended_yara_rule": None},
    {"rule_id": "RULE-2026-028", "rule_name": "RDP Session Hijacking Activity", "alert_spike_count_24h": 8, "noise_ratio": "0.0%", "top_offender_ip": "10.0.9.12", "top_user": "term_svc", "tuning_status": "CRITICAL_ALERT", "recommended_yara_rule": None},
    {"rule_id": "RULE-2026-029", "rule_name": "Suspicious Office Application Spawning CMD/PowerShell", "alert_spike_count_24h": 64, "noise_ratio": "15.6%", "top_offender_ip": "10.0.2.88", "top_user": "b_clark", "tuning_status": "ACTIVE_TRIAGE", "recommended_yara_rule": None},
    {"rule_id": "RULE-2026-030", "rule_name": "Outbound Traffic to Known Malicious C2 IP", "alert_spike_count_24h": 22, "noise_ratio": "0.0%", "top_offender_ip": "198.51.100.42", "top_user": "svc_export", "tuning_status": "CRITICAL_ALERT", "recommended_yara_rule": None},
    {"rule_id": "RULE-2026-031", "rule_name": "Process Hollowing in Explorer.exe", "alert_spike_count_24h": 4, "noise_ratio": "0.0%", "top_offender_ip": "10.0.3.11", "top_user": "t_white", "tuning_status": "CRITICAL_ALERT", "recommended_yara_rule": None},
    {"rule_id": "RULE-2026-032", "rule_name": "Ransomware File Extension Modification Spike", "alert_spike_count_24h": 2, "noise_ratio": "0.0%", "top_offender_ip": "10.0.7.55", "top_user": "shared_drive_svc", "tuning_status": "CRITICAL_ALERT", "recommended_yara_rule": None},
    {"rule_id": "RULE-2026-033", "rule_name": "Linux Kernel Exploit Attempt Detected", "alert_spike_count_24h": 7, "noise_ratio": "0.0%", "top_offender_ip": "192.168.1.105", "top_user": "www-data", "tuning_status": "CRITICAL_ALERT", "recommended_yara_rule": None},
    {"rule_id": "RULE-2026-034", "rule_name": "Excessive API Call Burst to Cloud Secrets Manager", "alert_spike_count_24h": 125, "noise_ratio": "32.0%", "top_offender_ip": "35.232.10.4", "top_user": "app_backend_sa", "tuning_status": "EXCLUSION_RECOMMENDED", "recommended_yara_rule": "exclude_secrets_rotation_cron"},
    {"rule_id": "RULE-2026-035", "rule_name": "SSH Key Added to Authorized_Keys File", "alert_spike_count_24h": 36, "noise_ratio": "8.3%", "top_offender_ip": "198.51.100.42", "top_user": "admin_root", "tuning_status": "ACTIVE_TRIAGE", "recommended_yara_rule": None}
]


@app.post("/api/v2/query", response_model=QueryResponse)
async def handle_query(request: QueryRequest):
    prompt = request.prompt.lower().strip()
    logger.info(f"Received query: {prompt}")

    try:
        if "epss" in prompt or "vulnerability" in prompt or "scc" in prompt:
            result = prioritize_vulnerabilities_v2()
        elif "correlate" in prompt or "udm" in prompt or "incident" in prompt:
            result = correlate_incidents_v2("ALT-1001")
        elif "soar" in prompt or "playbook" in prompt or "diagnos" in prompt:
            result = diagnose_soar_failures_v2()
        elif "intel" in prompt or "cve" in prompt or "advisory" in prompt or "news" in prompt or "trending" in prompt:
            result = get_threat_intel_summary(prompt)
        else:
            response = await root_agent.run(request.prompt)
            result = response.text if hasattr(response, 'text') else str(response)

        return QueryResponse(status="SUCCESS", prompt=request.prompt, result=result)
    except Exception as e:
        logger.error(f"Error executing agent query: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v2/dashboard/alerts")
def get_dashboard_alerts():
    alerts_list = generate_enterprise_100_alerts()
    return {
        "status": "SUCCESS",
        "total_alerts": len(alerts_list),
        "alerts": alerts_list
    }


@app.get("/api/v2/dashboard/detections")
def get_dashboard_detections():
    return {
        "status": "SUCCESS",
        "total_rules": len(ENTERPRISE_35_DETECTION_RULES),
        "detections": ENTERPRISE_35_DETECTION_RULES
    }


@app.get("/api/v2/dashboard/vulnerabilities")
def get_dashboard_vulnerabilities():
    intel_data = get_cached_threat_intel()
    cisa_cves = intel_data.get("cves", [])
    
    cve_dict = {}
    asset_rotation = ["gke-prod-frontend-pool", "bastion-jump-host", "prod-db-cluster-01", "edge-router-us-central1"]
    
    for idx, item in enumerate(cisa_cves):
        cid = item.get("cve_id")
        if cid:
            target_asset = asset_rotation[idx % len(asset_rotation)]
            cve_dict[cid] = {
                "cve_id": cid,
                "asset_id": target_asset,
                "cvss_score": item.get("cvss_score", 9.0),
                "internet_exposed": True if target_asset in ["gke-prod-frontend-pool", "bastion-jump-host", "edge-router-us-central1"] else False,
                "asset_criticality": "CRITICAL" if item.get("cvss_score", 9.0) >= 9.0 else "HIGH",
                "title": f"{item.get('vendor_project')} {item.get('vulnerability_name')}"
            }
            
    for cid, info in MOCK_SCC_FINDINGS_2026.items():
        if cid not in cve_dict:
            cve_dict[cid] = info
            
    all_cve_ids = list(cve_dict.keys())
    epss_map = fetch_epss_scores(all_cve_ids)
    
    vulnerabilities = []
    for cve, info in cve_dict.items():
        epss_info = epss_map.get(cve, {"epss": 0.88, "percentile": 0.95})
        cvss = info["cvss_score"]
        epss_prob = epss_info.get("epss", 0.88)
        exposure_mult = 1.5 if info["internet_exposed"] else 1.0
        asset_mult = 1.4 if info["asset_criticality"] == "CRITICAL" else (1.2 if info["asset_criticality"] == "HIGH" else 1.0)
        composite_risk = round(cvss * (1.0 + epss_prob) * exposure_mult * asset_mult, 2)
        
        vulnerabilities.append({
            "cve_id": cve,
            "title": info["title"],
            "asset_id": info["asset_id"],
            "cvss_score": cvss,
            "epss_probability": epss_prob,
            "epss_percentile": epss_info.get("percentile", 0.95),
            "internet_exposed": info["internet_exposed"],
            "asset_criticality": info["asset_criticality"],
            "composite_risk_score": composite_risk
        })
    
    vulnerabilities.sort(key=lambda x: x["composite_risk_score"], reverse=True)
    return {
        "status": "SUCCESS",
        "source": "Google SCC & Live 2026 CISA KEV & FIRST EPSS API",
        "total_vulnerabilities": len(vulnerabilities),
        "vulnerabilities": vulnerabilities
    }


@app.get("/api/v2/dashboard/telemetry")
def get_dashboard_telemetry():
    events = get_recent_udm_events()
    return {
        "status": "SUCCESS",
        "total_events": len(events),
        "telemetry_stream": events
    }


@app.get("/api/v2/dashboard/threat_intel")
def get_dashboard_threat_intel():
    intel = get_cached_threat_intel()
    return {
        "status": "SUCCESS",
        "last_updated": intel["last_updated"],
        "total_cves": len(intel["cves"]),
        "total_advisories": len(intel["advisories"]),
        "daily_cves": intel["cves"],
        "security_advisories": intel["advisories"]
    }


# Mount Static Files for UI
app.mount("/", StaticFiles(directory="frontend/static", html=True), name="static")
