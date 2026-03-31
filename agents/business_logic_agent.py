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


INVARIANT_TEMPLATES = [
    {
        "id": "privileged_routes_require_auth",
        "name": "Privileged route access control",
        "category": "access_control",
        "severity": "high",
        "routes": ["/admin", "/admin/dashboard", "/management", "/internal"],
        "success_markers": ["admin", "dashboard", "manage users", "settings"],
        "negative_markers": ["login", "sign in", "unauthorized", "forbidden"],
        "finding": {
            "type": "business_logic_access_control",
            "status": "Potentially Exposed",
            "description": "Privileged route appears reachable without explicit authentication challenge"
        }
    },
    {
        "id": "checkout_completion_requires_previous_steps",
        "name": "Checkout completion order enforcement",
        "category": "workflow",
        "severity": "high",
        "requires_markers": ["checkout"],
        "routes": ["/checkout/complete", "/payment/success", "/order/confirmation", "/checkout/finalize"],
        "success_markers": ["order confirmed", "payment success", "thank you", "confirmation"],
        "finding": {
            "type": "business_logic_workflow_bypass",
            "status": "Potentially Exploitable",
            "description": "Completion endpoint may be reachable without validated prior checkout steps"
        }
    },
    {
        "id": "account_routes_require_authentication",
        "name": "Account route authentication",
        "category": "authentication",
        "severity": "medium",
        "requires_markers": ["authentication"],
        "routes": ["/account", "/profile", "/user/settings"],
        "success_markers": ["profile", "account", "settings"],
        "negative_markers": ["login", "sign in", "session expired", "unauthorized"],
        "finding": {
            "type": "business_logic_authentication_gap",
            "status": "Suspicious Exposure",
            "description": "Account-related route appears accessible without clear authentication barrier"
        }
    },
    {
        "id": "approval_routes_require_authorization",
        "name": "Approval workflow authorization",
        "category": "workflow",
        "severity": "high",
        "routes": ["/approve", "/approval/complete", "/workflow/approve", "/admin/approve"],
        "success_markers": ["approved", "approval complete", "request approved"],
        "negative_markers": ["login", "forbidden", "unauthorized"],
        "finding": {
            "type": "business_logic_approval_bypass",
            "status": "Potentially Exploitable",
            "description": "Approval endpoint may be directly callable without proper role or state validation"
        }
    },
    {
        "id": "coupon_usage_enforces_limits",
        "name": "Coupon single-use and validity controls",
        "category": "commerce",
        "severity": "medium",
        "requires_markers": ["discounts"],
        "routes": ["/coupon/apply", "/promo/apply", "/discount/apply"],
        "success_markers": ["discount applied", "coupon applied", "promo applied"],
        "negative_markers": ["invalid coupon", "expired", "limit reached"],
        "finding": {
            "type": "business_logic_coupon_abuse",
            "status": "Potentially Exploitable",
            "description": "Discount application route may allow coupon abuse through weak state validation"
        }
    }
]


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
        template_results = self._run_invariant_templates(target, workflow_markers)
        vulnerabilities = template_results.get("vulnerabilities", [])
        templates_tested = template_results.get("templates_tested", [])
        triggered_templates = template_results.get("triggered_templates", [])

        for vuln in vulnerabilities:
            self.add_finding(vuln)

        self.set_progress(1.0, "Business-logic analysis complete")
        return TaskResult(
            task_id=task.get("id", ""),
            success=True,
            data={
                "workflow_markers": workflow_markers,
                "vulnerabilities": vulnerabilities,
                "invariants_tested": templates_tested,
                "templates_triggered": triggered_templates
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

    def _run_invariant_templates(self, target: str, workflow_markers: Dict[str, bool]) -> Dict[str, Any]:
        vulnerabilities: List[Dict[str, Any]] = []
        templates_tested: List[str] = []
        triggered_templates: List[str] = []

        for template in INVARIANT_TEMPLATES:
            required_markers = template.get("requires_markers", [])
            if required_markers and not all(workflow_markers.get(marker, False) for marker in required_markers):
                continue

            templates_tested.append(template["id"])
            finding = self._execute_template(target, template)
            if finding:
                vulnerabilities.append(finding)
                triggered_templates.append(template["id"])

        return {
            "vulnerabilities": vulnerabilities,
            "templates_tested": templates_tested,
            "triggered_templates": triggered_templates
        }

    def _execute_template(self, target: str, template: Dict[str, Any]) -> Dict[str, Any]:
        routes = template.get("routes", [])
        success_markers = [m.lower() for m in template.get("success_markers", [])]
        negative_markers = [m.lower() for m in template.get("negative_markers", [])]

        for route in routes:
            url = urljoin(target.rstrip("/") + "/", route.lstrip("/"))
            try:
                response = requests.get(url, timeout=8, allow_redirects=False)
                body = (response.text or "").lower()

                if response.status_code != 200:
                    continue

                has_success_marker = any(m in body for m in success_markers) if success_markers else True
                has_negative_marker = any(m in body for m in negative_markers)

                if has_success_marker and not has_negative_marker:
                    finding_meta = template.get("finding", {})
                    return {
                        "type": finding_meta.get("type", "business_logic_issue"),
                        "severity": template.get("severity", "medium"),
                        "status": finding_meta.get("status", "Potentially Exploitable"),
                        "location": url,
                        "description": finding_meta.get("description", "Business-logic invariant may be violated"),
                        "evidence": f"HTTP {response.status_code} on {route} without clear challenge markers",
                        "invariant_template": template.get("id"),
                        "invariant_category": template.get("category")
                    }
            except Exception:
                continue

        return {}
