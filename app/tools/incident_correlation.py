# Copyright 2026 Google LLC
# Entity Overlap Incident Correlation & Pre-Merging Tool

import json
from typing import Optional

SAMPLE_ALERT_DATABASE = {
    "ALT-1001": {
        "alert_id": "ALT-1001",
        "rule_id": "RULE-SSH-BRUTE",
        "alert_name": "Suspicious SSH Brute Force Ingress",
        "source_ip": "198.51.100.42",
        "target_host": "prod-db-cluster-01",
        "target_user": "admin_root",
        "status": "OPEN",
        "timestamp": "2026-10-03T16:00:00Z"
    },
    "ALT-1002": {
        "alert_id": "ALT-1002",
        "rule_id": "RULE-PRIV-ESC",
        "alert_name": "Unusual Sudo Privilege Escalation",
        "source_ip": "198.51.100.42",
        "target_host": "prod-db-cluster-01",
        "target_user": "admin_root",
        "status": "OPEN",
        "timestamp": "2026-10-03T16:05:00Z"
    },
    "ALT-1003": {
        "alert_id": "ALT-1003",
        "rule_id": "RULE-DATA-EGRESS",
        "alert_name": "Anymmetrical Outbound Data Egress",
        "source_ip": "198.51.100.42",
        "target_host": "prod-db-cluster-01",
        "target_user": "svc_export",
        "status": "OPEN",
        "timestamp": "2026-10-03T16:12:00Z"
    }
}


def correlate_incidents_v2(alert_id: str = "ALT-1001") -> str:
    """Calculates deterministic entity overlap (IP, Host, User) across recent SecOps alerts to recommend incident pre-merges.

    Args:
        alert_id: Primary alert ID to correlate against (e.g., 'ALT-1001').

    Returns:
        JSON string detailing entity overlap scores, correlated alert IDs, and merge recommendations.
    """
    target_alert = SAMPLE_ALERT_DATABASE.get(alert_id)
    if not target_alert:
        return json.dumps({
            "status": "ERROR",
            "message": f"Alert ID '{alert_id}' not found in active alerts dataset."
        })
    
    primary_ip = target_alert.get("source_ip")
    primary_host = target_alert.get("target_host")
    primary_user = target_alert.get("target_user")
    
    correlated_alerts = []
    
    for aid, alert in SAMPLE_ALERT_DATABASE.items():
        if aid == alert_id:
            continue
        
        shared_entities = []
        if alert.get("source_ip") == primary_ip:
            shared_entities.append(f"Source IP ({primary_ip})")
        if alert.get("target_host") == primary_host:
            shared_entities.append(f"Target Host ({primary_host})")
        if alert.get("target_user") == primary_user:
            shared_entities.append(f"Target User ({primary_user})")
        
        if shared_entities:
            # Overlap Confidence Score (1 entity = 0.60, 2 entities = 0.85, 3 entities = 0.98)
            confidence_score = 0.60 + (0.25 if len(shared_entities) >= 2 else 0.0) + (0.13 if len(shared_entities) == 3 else 0.0)
            
            correlated_alerts.append({
                "alert_id": aid,
                "alert_name": alert.get("alert_name"),
                "shared_entities": shared_entities,
                "confidence_score": round(confidence_score, 2),
                "recommended_action": "PRE_MERGE_INTO_PRIMARY"
            })
    
    output = {
        "status": "SUCCESS",
        "primary_alert_id": alert_id,
        "primary_alert_name": target_alert.get("alert_name"),
        "total_correlated": len(correlated_alerts),
        "overall_correlation_score": max([c["confidence_score"] for c in correlated_alerts]) if correlated_alerts else 0.0,
        "correlated_alerts": correlated_alerts,
        "merge_recommendation": f"Merge alerts {[c['alert_id'] for c in correlated_alerts]} into primary incident '{alert_id}' to consolidate SOC incident graph."
    }
    
    return json.dumps(output, indent=2)
