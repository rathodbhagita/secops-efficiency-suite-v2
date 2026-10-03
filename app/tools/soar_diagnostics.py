# Copyright 2026 Google LLC
# SOAR Playbook Execution Diagnostics Tool

import json

SAMPLE_SOAR_EXECUTION_LOGS = [
    {
        "execution_id": "SOAR-EXEC-9012",
        "playbook_name": "PB-ISOLATE-COMPUTE",
        "status": "FAILED",
        "step_failed": "ggc_compute_isolate_v1",
        "error_code": "PERMISSION_DENIED_403",
        "error_message": "403 Forbidden: Missing 'iam.serviceAccounts.actAs' on target service account 'soar-worker-sa@qwiklabs-gcp-02-3e0fee61b7b8.iam.gserviceaccount.com'",
        "timestamp": "2026-10-03T16:20:00Z"
    },
    {
        "execution_id": "SOAR-EXEC-9013",
        "playbook_name": "PB-CONTAIN-IAM-USER",
        "status": "FAILED",
        "step_failed": "revoke_user_session_v2",
        "error_code": "RESOURCE_NOT_FOUND_404",
        "error_message": "404 Not Found: User identity 'j.doe_temp@company.internal' not found in Cloud Identity Directory sync.",
        "timestamp": "2026-10-03T16:25:00Z"
    }
]


def diagnose_soar_failures_v2() -> str:
    """Reads failed SOAR playbook execution logs and generates root cause diagnoses and automated IAM/code remediation steps.

    Returns:
        JSON string detailing playbook failure root causes, affected steps, and preventive fix actions.
    """
    diagnostics = []
    
    for log in SAMPLE_SOAR_EXECUTION_LOGS:
        exec_id = log.get("execution_id")
        playbook = log.get("playbook_name")
        step = log.get("step_failed")
        err_msg = log.get("error_message")
        
        if "403" in err_msg or "PERMISSION_DENIED" in log.get("error_code"):
            root_cause = "Missing Cloud IAM Role bindings for SOAR Execution Service Account."
            fix_recommendation = (
                "Grant role 'roles/compute.instanceAdmin.v1' and 'roles/iam.serviceAccountUser' "
                "to service account 'soar-worker-sa@qwiklabs-gcp-02-3e0fee61b7b8.iam.gserviceaccount.com'."
            )
        elif "404" in err_msg or "NOT_FOUND" in log.get("error_code"):
            root_cause = "Transient directory sync delay between Directory API and Cloud Identity."
            fix_recommendation = (
                "Add 5-second exponential backoff retry loop to 'revoke_user_session_v2' step in SOAR Playbook editor."
            )
        else:
            root_cause = "Unhandled execution exception during automated API call."
            fix_recommendation = "Review Playbook step timeout and exception handling configurations."
        
        diagnostics.append({
            "execution_id": exec_id,
            "playbook_name": playbook,
            "failed_step": step,
            "error_code": log.get("error_code"),
            "root_cause": root_cause,
            "preventive_fix": fix_recommendation
        })
    
    report = {
        "status": "SUCCESS",
        "total_failures_diagnosed": len(diagnostics),
        "diagnostics": diagnostics
    }
    
    return json.dumps(report, indent=2)
