"""
PDF Report Generation
"""

from typing import Dict, Any, List
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class ReportGenerator:
    """
    Generate a professional penetration test report.
    """
    
    def __init__(self):
        self.timestamp = datetime.now()
    
    def generate_report_dict(self, state: dict) -> Dict[str, Any]:
        """
        Generate report as a dictionary (can be converted to PDF, JSON, etc.)
        """

        findings = self._generate_findings(state)
        validation = state.get("validation", {}) or {}
        
        report = {
            "metadata": {
                "title": "Penetration Test Report",
                "date": self.timestamp.isoformat(),
                "target": state.get("target"),
                "target_type": state.get("target_type"),
                "mode": state.get("mode", "classic"),
                "llm_model": state.get("llm_model", "unknown"),
                "report_version": "2.0",
            },
            "executive_summary": self._generate_summary(state),
            "findings": findings,
            "assessment_phases": self._generate_assessment_phases(state),
            "methodologies": self._generate_methodology(state),
            "statistics": self._generate_statistics(state),
            "recommendations": self._generate_recommendations(state),
            "remediation_plan": self._generate_remediation_plan(findings),
            "validation": validation,
            "appendix": self._generate_appendix(state),
        }
        
        return report
    
    def _generate_summary(self, state: dict) -> Dict[str, Any]:
        """Generate executive summary"""
        vulnerabilities = state.get("vulnerabilities", []) or []
        vuln_count = len(vulnerabilities)
        critical_count = len([v for v in vulnerabilities if str(v.get("severity", "")).lower() == "critical"])
        high_count = len([v for v in vulnerabilities if str(v.get("severity", "")).lower() == "high"])
        
        risk_level = "CRITICAL" if critical_count > 0 else "HIGH" if high_count > 0 else "MEDIUM"
        
        return {
            "risk_level": risk_level,
            "vulnerabilities_found": vuln_count,
            "critical_vulnerabilities": critical_count,
            "high_vulnerabilities": high_count,
            "services_tested": list((state.get("scanned_ports") or {}).values()),
            "summary_text": f"Penetration test of {state['target']} identified {vuln_count} vulnerabilities "
                           f"({critical_count} critical, {high_count} high). "
                           f"Risk level: {risk_level}"
        }
    
    def _generate_findings(self, state: dict) -> List[Dict[str, Any]]:
        """Format vulnerability findings"""
        
        findings = []
        
        for vuln in state.get("vulnerabilities", []):
            severity = str(vuln.get("severity", "medium")).lower()
            finding = {
                "id": vuln.get("vulnerability_id", "N/A"),
                "type": vuln.get("type", "unknown"),
                "severity": severity,
                "location": vuln.get("location", "unknown"),
                "description": vuln.get("description", ""),
                "evidence": vuln.get("evidence", ""),
                "exploitation_status": vuln.get("exploitation_status", "unknown"),
                "confidence_score": self._derive_confidence(vuln),
                "evidence_strength": vuln.get("evidence_strength") or self._derive_evidence_strength(vuln),
                "validation": vuln.get("validation"),
                "attack_family": vuln.get("attack_family"),
                "attack_variant": vuln.get("attack_variant"),
                "remediation": self._get_remediation(vuln.get("type", "unknown")),
            }
            findings.append(finding)
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings.sort(key=lambda x: severity_order.get(x["severity"], 999))
        
        return findings

    def _derive_confidence(self, vuln: Dict[str, Any]) -> int:
        """Fallback confidence score when the source finding has none."""

        raw = vuln.get("confidence_score")
        try:
            if raw is not None:
                return max(0, min(100, int(float(raw))))
        except (TypeError, ValueError):
            pass

        validation = vuln.get("validation") or {}
        if isinstance(validation, dict):
            if validation.get("confirmed") is True:
                return 95
            raw_validation_conf = validation.get("confidence")
            try:
                if raw_validation_conf is not None:
                    val = float(raw_validation_conf)
                    if val <= 1:
                        val *= 100
                    return max(0, min(100, int(round(val))))
            except (TypeError, ValueError):
                pass

        status = str(vuln.get("exploitation_status", vuln.get("status", ""))).lower()
        severity = str(vuln.get("severity", "medium")).lower()

        if status == "confirmed":
            return 95
        if status == "potential":
            return 65
        if status in {"bypass_confirmed", "executed"}:
            return 90
        if severity == "critical":
            return 85
        if severity == "high":
            return 75
        if severity == "medium":
            return 55
        if severity == "low":
            return 35
        return 25

    def _derive_evidence_strength(self, vuln: Dict[str, Any]) -> str:
        """Provide a readable evidence-strength label when missing."""

        status = str(vuln.get("exploitation_status", vuln.get("status", ""))).lower()
        if status == "confirmed":
            return "strong"
        if status == "potential":
            return "moderate"
        return "moderate"
    
    def _generate_methodology(self, state: dict) -> Dict[str, Any]:
        """Document testing methodology"""
        
        return {
            "approach": "Comprehensive Security Assessment",
            "phases": [
                "1. Reconnaissance and Scanning",
                "2. Vulnerability Assessment",
                "3. Exploitation Attempts",
                "4. Analysis and Reporting"
            ],
            "tools_used": ["Nmap", "SQLmap", "Curl", "Hydra"],
            "testing_duration_seconds": sum(
                e.get("execution_time", 0) for e in state.get("execution_history", [])
            ),
            "total_scans": len(state.get("execution_history", []))
        }

    def _generate_assessment_phases(self, state: dict) -> List[Dict[str, Any]]:
        """Create a compact phase summary for dashboard and HTML reports."""

        vulnerabilities = state.get("vulnerabilities", []) or []
        execution_history = state.get("execution_history", []) or []
        validation = state.get("validation", {}) or {}

        return [
            {
                "phase": "reconnaissance",
                "type": "Discovery",
                "content": f"Identified {len((state.get('scanned_ports') or {}))} scanned services and {len(state.get('reflections', []))} reasoning loops.",
                "status": "completed" if execution_history else "pending",
            },
            {
                "phase": "vulnerability_analysis",
                "type": "Triage",
                "content": f"Validated {len(vulnerabilities)} findings across the active assessment surface.",
                "status": "completed" if vulnerabilities else "pending",
            },
            {
                "phase": "exploitation_planning",
                "type": "Planning",
                "content": f"Execution history contains {len(execution_history)} tool actions and retry decisions.",
                "status": "completed" if execution_history else "pending",
            },
            {
                "phase": "impact_assessment",
                "type": "Reporting",
                "content": f"Risk level {self._generate_summary(state)['risk_level']} with {validation.get('confirmed', 0)} confirmed validations.",
                "status": "completed" if state.get("vulnerabilities") else "pending",
            },
        ]
    
    def _generate_statistics(self, state: dict) -> Dict[str, Any]:
        """Generate testing statistics"""
        
        return {
            "total_loops": state.get("loop_count", 0),
            "total_executions": state.get("total_executions", len(state.get("execution_history", []))),
            "successful_executions": len([e for e in state.get("execution_history", []) 
                                         if e["return_code"] == 0]),
            "failed_executions": len([e for e in state.get("execution_history", []) 
                                     if e["return_code"] != 0]),
            "reflections_performed": len(state.get("reflections", [])),
            "average_reflection_confidence": (
                sum(r.get("confidence", 0) for r in state.get("reflections", [])) / len(state.get("reflections", []))
                if state.get("reflections") else 0
            )
        }
    
    def _generate_recommendations(self, state: dict) -> List[Dict[str, str]]:
        """Generate remediation recommendations"""
        
        recommendations = []
        vulnerabilities = state.get("vulnerabilities", []) or []
        
        # Critical vulnerabilities need immediate action
        critical = [v for v in vulnerabilities if str(v.get("severity", "")).lower() == "critical"]
        if critical:
            recommendations.append({
                "priority": "CRITICAL",
                "action": "Immediately address all critical vulnerabilities",
                "rationale": "Critical vulnerabilities pose immediate risk of system compromise"
            })
        
        # SQL injection
        if any(str(v.get("type", "")).lower() == "sql_injection" for v in vulnerabilities):
            recommendations.append({
                "priority": "HIGH",
                "action": "Implement parameterized queries and input validation",
                "rationale": "SQL injection allows unauthorized database access"
            })
        
        # Weak credentials
        if any(str(v.get("type", "")).lower() == "weak_credentials" for v in vulnerabilities):
            recommendations.append({
                "priority": "HIGH",
                "action": "Enforce strong password policies and multi-factor authentication",
                "rationale": "Weak credentials enable unauthorized access"
            })
        
        # General recommendations
        recommendations.extend([
            {
                "priority": "HIGH",
                "action": "Implement a Web Application Firewall (WAF)",
                "rationale": "WAF can detect and block common attack patterns"
            },
            {
                "priority": "MEDIUM",
                "action": "Regular security updates and patch management",
                "rationale": "Keep systems updated to prevent known vulnerability exploitation"
            },
            {
                "priority": "MEDIUM",
                "action": "Implement comprehensive logging and monitoring",
                "rationale": "Enable detection of security incidents and unauthorized access"
            }
        ])
        
        return recommendations

    def _generate_remediation_plan(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert findings into a remediation-first action plan."""

        plan = []
        for finding in findings:
            severity = str(finding.get("severity", "medium")).lower()
            plan.append({
                "priority": severity.upper(),
                "finding_type": finding.get("type", "unknown"),
                "location": finding.get("location", "unknown"),
                "remediation": finding.get("remediation", "Address this vulnerability per security best practices"),
                "verification": "Re-run remediation verification after the fix is deployed.",
                "status": finding.get("validation", {}).get("confirmed", False) and "confirmed" or "unconfirmed",
            })

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        plan.sort(key=lambda item: severity_order.get(item["priority"].lower(), 999))
        return plan
    
    def _generate_appendix(self, state: dict) -> Dict[str, Any]:
        """Generate technical appendix with execution details"""
        
        return {
            "execution_log": [
                {
                    "tool": e.get("tool_name"),
                    "status": getattr(e.get("status"), "value", e.get("status")),
                    "time": e.get("execution_time", 0),
                    "args": str(e.get("tool_args", {}))
                }
                for e in state.get("execution_history", [])[:20]  # Last 20 executions
            ],
            "errors_encountered": state.get("errors", []),
            "warnings": state.get("warnings", []),
            "validation_summary": state.get("validation", {}),
        }
    
    def _get_remediation(self, vulnerability_type: str) -> str:
        """Get generic remediation for vulnerability type"""
        
        remediations = {
            "sql_injection": "Use prepared statements and parameterized queries",
            "weak_credentials": "Enforce strong password policies and MFA",
            "exposed_port": "Close unnecessary ports and implement firewall rules",
            "cross_site_scripting": "Implement input validation and output encoding",
            "authentication_bypass": "Implement proper session management and access controls",
        }
        
        return remediations.get(str(vulnerability_type).lower(), "Address this vulnerability per security best practices")
