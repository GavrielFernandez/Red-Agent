"""Cloud posture review plugin for safe configuration auditing."""

from __future__ import annotations

from typing import Any, Dict, List
import json
import os
import time

try:
    from red_agent.tools.tool_factory import BaseTool
except ImportError:
    from tools.tool_factory import BaseTool


class CloudPostureTool(BaseTool):
    """Audit cloud configuration artifacts for common posture issues."""

    def __init__(self):
        super().__init__("cloud_posture", timeout=60, max_retries=0)

    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        profile = str(params.get("profile", "default")).strip().lower() or "default"
        target = str(params.get("target", "")).strip()
        start = time.time()

        findings: List[Dict[str, Any]] = []
        checks = self._build_checks()

        for check in checks:
            if check["predicate"]():
                findings.append({
                    "id": check["id"],
                    "title": check["title"],
                    "severity": check["severity"],
                    "evidence": check["evidence_text"],
                    "remediation": check["remediation"],
                })

        summary = {
            "profile": profile,
            "target": target or "workspace-environment",
            "issues_found": len(findings),
            "checks_run": len(checks),
            "status": "review_complete",
        }

        elapsed = time.time() - start
        return {
            "stdout": json.dumps(summary, indent=2),
            "stderr": "",
            "return_code": 0,
            "status": "success",
            "error_message": None,
            "execution_time": elapsed,
            "retries_used": 0,
            "metadata": {
                "summary": summary,
                "findings": findings,
            },
        }

    def _build_checks(self) -> List[Dict[str, Any]]:
        env = os.environ
        return [
            {
                "id": "cloud-auth-disabled",
                "title": "Authentication is not enforced by default",
                "severity": "high",
                "evidence_text": "REDAGENT_ENABLE_AUTH is not set to true",
                "remediation": "Enable authentication and role-based access control for all dashboard and API routes.",
                "predicate": lambda: env.get("REDAGENT_ENABLE_AUTH", "false").lower() != "true",
            },
            {
                "id": "cloud-secret-default",
                "title": "Default secret key detected",
                "severity": "high",
                "evidence_text": "REDAGENT_SECRET_KEY still uses the default insecure value",
                "remediation": "Set a unique secret key from a secure secret store.",
                "predicate": lambda: env.get("REDAGENT_SECRET_KEY", "default-insecure-key") == "default-insecure-key",
            },
            {
                "id": "cloud-allow-all-cors",
                "title": "Permissive CORS policy detected",
                "severity": "medium",
                "evidence_text": "REDAGENT_CORS_ORIGINS allows all origins",
                "remediation": "Restrict CORS to trusted origins only.",
                "predicate": lambda: env.get("REDAGENT_CORS_ORIGINS", "*") == "*",
            },
            {
                "id": "cloud-public-buckets-scan",
                "title": "Public storage audit required",
                "severity": "info",
                "evidence_text": "Cloud bucket posture review should be verified in the target environment",
                "remediation": "Check S3/GCS/Azure storage for public access and overly broad policies in a controlled cloud environment.",
                "predicate": lambda: True,
            },
        ]


def register_tools() -> Dict[str, BaseTool]:
    return {"cloud_posture": CloudPostureTool()}
