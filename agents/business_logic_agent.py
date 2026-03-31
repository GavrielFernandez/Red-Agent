"""
Business Logic Agent
====================

Detects workflow and authorization logic weaknesses that are often missed by
classic scanners (for example, step skipping and unguarded privileged routes).
"""

import logging
from typing import Any, Dict, List
from urllib.parse import urljoin

import requests

from .base_agent import BaseAgent, AgentCapability, TaskResult

logger = logging.getLogger(__name__)


class BusinessLogicAgent(BaseAgent):
    """Specialized agent for workflow and business-logic flaw detection."""

    def __init__(self, llm_client: Any = None, **kwargs):
        super().__init__(name="BusinessLogicAgent", llm_client=llm_client, **kwargs)

    @property
    def capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="business_logic_analysis",
                description="Analyze business workflows for logic abuse scenarios",
                input_types=["target", "recon", "workflow"],
                output_types=["vulnerabilities", "invariants", "workflow_map"]
            )
        ]

    async def execute_task(self, task: Dict[str, Any]) -> TaskResult:
        task_type = task.get("type", "")
        if task_type == "business_logic_scan":
            return await self._scan_business_logic(task)

        return TaskResult(
            task_id=task.get("id", ""),
            success=False,
            error=f"Unknown task type: {task_type}"
        )

    async def _scan_business_logic(self, task: Dict[str, Any]) -> TaskResult:
        target = task.get("target", "")
        if not target:
            return TaskResult(task_id=task.get("id", ""), success=False, error="Missing target")

        self.set_progress(0.2, "Discovering workflow markers")
        page_data = self._fetch_page(target)
        text = (page_data.get("body", "") or "").lower()

        workflow_markers = {
            "checkout": any(k in text for k in ["checkout", "cart", "payment", "order"]),
            "authentication": any(k in text for k in ["login", "signin", "password", "account"]),
            "administration": any(k in text for k in ["admin", "dashboard", "manage users", "settings"]),
            "discounts": any(k in text for k in ["coupon", "promo", "discount"])
        }

        self.set_progress(0.55, "Testing workflow invariants")
        vulnerabilities = []

        # Invariant: privileged routes should not be publicly accessible.
        vulnerabilities.extend(self._check_privileged_route_access(target))

        # Invariant: critical flow completion routes should require prior steps.
        if workflow_markers["checkout"]:
            vulnerabilities.extend(self._check_checkout_step_bypass(target))

        # Invariant: account management routes should enforce authentication.
        if workflow_markers["authentication"]:
            vulnerabilities.extend(self._check_account_route_exposure(target))

        for vuln in vulnerabilities:
            self.add_finding(vuln)

        self.set_progress(1.0, "Business-logic analysis complete")
        return TaskResult(
            task_id=task.get("id", ""),
            success=True,
            data={
                "workflow_markers": workflow_markers,
                "vulnerabilities": vulnerabilities,
                "invariants_tested": [
                    "privileged_routes_require_auth",
                    "checkout_completion_requires_previous_steps",
                    "account_routes_require_authentication"
                ]
            }
        )

    def _fetch_page(self, target: str) -> Dict[str, Any]:
        try:
            response = requests.get(target, timeout=10, allow_redirects=True)
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text[:300000]
            }
        except Exception as e:
            logger.debug(f"BusinessLogicAgent fetch failed for {target}: {e}")
            return {"status_code": 0, "headers": {}, "body": ""}

    def _check_privileged_route_access(self, target: str) -> List[Dict[str, Any]]:
        findings = []
        candidates = ["/admin", "/admin/dashboard", "/management", "/internal"]

        for route in candidates:
            url = urljoin(target.rstrip("/") + "/", route.lstrip("/"))
            try:
                r = requests.get(url, timeout=8, allow_redirects=False)
                body = (r.text or "").lower()

                # Heuristic: 200 without an auth challenge page is suspicious.
                if r.status_code == 200 and not any(k in body for k in ["login", "sign in", "unauthorized"]):
                    findings.append({
                        "type": "business_logic_access_control",
                        "severity": "high",
                        "status": "Potentially Exposed",
                        "location": url,
                        "description": "Privileged route appears reachable without explicit authentication challenge",
                        "evidence": f"HTTP {r.status_code} on privileged endpoint"
                    })
                    break
            except Exception:
                continue

        return findings

    def _check_checkout_step_bypass(self, target: str) -> List[Dict[str, Any]]:
        findings = []
        candidates = [
            "/checkout/complete",
            "/payment/success",
            "/order/confirmation",
            "/checkout/finalize"
        ]

        for route in candidates:
            url = urljoin(target.rstrip("/") + "/", route.lstrip("/"))
            try:
                r = requests.get(url, timeout=8, allow_redirects=False)
                body = (r.text or "").lower()
                success_keywords = ["order confirmed", "payment success", "thank you", "confirmation"]

                if r.status_code == 200 and any(k in body for k in success_keywords):
                    findings.append({
                        "type": "business_logic_workflow_bypass",
                        "severity": "high",
                        "status": "Potentially Exploitable",
                        "location": url,
                        "description": "Completion endpoint may be reachable without validated prior checkout steps",
                        "evidence": f"HTTP {r.status_code} with success markers on direct access"
                    })
                    break
            except Exception:
                continue

        return findings

    def _check_account_route_exposure(self, target: str) -> List[Dict[str, Any]]:
        findings = []
        candidates = ["/account", "/profile", "/user/settings"]

        for route in candidates:
            url = urljoin(target.rstrip("/") + "/", route.lstrip("/"))
            try:
                r = requests.get(url, timeout=8, allow_redirects=False)
                body = (r.text or "").lower()

                if r.status_code == 200 and not any(k in body for k in ["login", "sign in", "session expired"]):
                    findings.append({
                        "type": "business_logic_authentication_gap",
                        "severity": "medium",
                        "status": "Suspicious Exposure",
                        "location": url,
                        "description": "Account-related route appears accessible without clear authentication barrier",
                        "evidence": f"HTTP {r.status_code} on account route"
                    })
                    break
            except Exception:
                continue

        return findings
