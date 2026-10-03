# Copyright 2026 Google LLC
# Live UDM Telemetry Event Generator & Stream Buffer

import asyncio
import random
from datetime import datetime, timezone
from typing import List, Dict

RECENT_UDM_EVENTS: List[Dict] = []
MAX_BUFFER_SIZE = 50

SAMPLE_PRINCIPALS = [
    {"hostname": "workstation-mac-04", "ip": "10.0.1.45", "user": {"userid": "a.smith@company.internal", "user_displayName": "Alice Smith"}},
    {"hostname": "prod-app-server-01", "ip": "10.0.4.15", "user": {"userid": "svc_scanner", "user_displayName": "Scanner Service"}},
    {"hostname": "bastion-host-01", "ip": "198.51.100.42", "user": {"userid": "admin_root", "user_displayName": "Root Administrator"}},
    {"hostname": "developer-laptop-12", "ip": "10.0.2.88", "user": {"userid": "dev_user", "user_displayName": "Developer User"}}
]

SAMPLE_TARGETS = [
    {"hostname": "prod-db-cluster-01", "ip": "10.0.10.5", "resource": "//cloudresourcemanager.googleapis.com/projects/366481817958"},
    {"hostname": "gke-prod-frontend-pool", "ip": "10.0.12.20", "resource": "//container.googleapis.com/clusters/prod-cluster"},
    {"hostname": "auth-service-backend", "ip": "10.0.8.12", "resource": "//iam.googleapis.com/serviceAccounts/soar-worker"}
]

EVENT_TYPES = ["USER_LOGIN", "PROCESS_EXECUTION", "NETWORK_CONNECTION", "SECURITY_ALERT"]


def generate_random_udm_event() -> Dict:
    principal = random.choice(SAMPLE_PRINCIPALS)
    target = random.choice(SAMPLE_TARGETS)
    event_type = random.choice(EVENT_TYPES)
    now_iso = datetime.now(timezone.utc).isoformat()
    
    return {
        "metadata": {
            "event_type": event_type,
            "event_timestamp": now_iso,
            "vendor_name": "Google",
            "product_name": "Google SecOps",
            "product_event_type": f"secops.{event_type.lower()}"
        },
        "principal": principal,
        "target": target,
        "network": {
            "ip_protocol": random.choice(["TCP", "UDP"]),
            "direction": random.choice(["INBOUND", "OUTBOUND"]),
            "application_protocol": random.choice(["HTTPS", "SSH", "DNS", "gRPC"])
        },
        "security_result": {
            "action": random.choice(["ALLOW", "ALLOW", "ALLOW", "AUDIT", "BLOCK"]),
            "category": "NETWORK_DETECTION",
            "severity": random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
            "description": f"SecOps UDM Telemetry Event: {event_type} observed between {principal['hostname']} and {target['hostname']}"
        }
    }


def seed_initial_events():
    global RECENT_UDM_EVENTS
    if not RECENT_UDM_EVENTS:
        for _ in range(15):
            RECENT_UDM_EVENTS.insert(0, generate_random_udm_event())


async def start_telemetry_stream():
    """Background task generating live SecOps UDM events every 15-30 seconds."""
    seed_initial_events()
    while True:
        await asyncio.sleep(15)
        new_event = generate_random_udm_event()
        RECENT_UDM_EVENTS.insert(0, new_event)
        if len(RECENT_UDM_EVENTS) > MAX_BUFFER_SIZE:
            RECENT_UDM_EVENTS.pop()


def get_recent_udm_events() -> List[Dict]:
    if not RECENT_UDM_EVENTS:
        seed_initial_events()
    return RECENT_UDM_EVENTS
