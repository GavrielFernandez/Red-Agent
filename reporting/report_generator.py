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
        
        report = {
            "metadata": {
                "title": "Penetration Test Report",
                "date": self.timestamp.isoformat(),
                "target": state.get("target"),
                "target_type": state.get("target_type"),
            },
            "executive_summary": self._generate_summary(state),
            "findings": self._generate_findings(state),
            "methodologies": self._generate_methodology(state),
            "statistics": self._generate_statistics(state),
            "recommendations": self._generate_recommendations(state),
            "appendix": self._generate_appendix(state),
        }
        
        return report
    
    def _generate_summary(self, state: dict) -> Dict[str, Any]:
        """Generate executive summary"""
        
        vuln_count = len(state["vulnerabilities"])
        critical_count = len([v for v in state["vulnerabilities"] if v["severity"] == "critical"])
        high_count = len([v for v in state["vulnerabilities"] if v["severity"] == "high"])
        
        risk_level = "CRITICAL" if critical_count > 0 else "HIGH" if high_count > 0 else "MEDIUM"
        
        return {
            "risk_level": risk_level,
            "vulnerabilities_found": vuln_count,
            "critical_vulnerabilities": critical_count,
            "high_vulnerabilities": high_count,
            "services_tested": list(state["scanned_ports"].values()),
            "summary_text": f"Penetration test of {state['target']} identified {vuln_count} vulnerabilities "
                           f"({critical_count} critical, {high_count} high). "
                           f"Risk level: {risk_level}"
        }
    
    def _generate_findings(self, state: dict) -> List[Dict[str, Any]]:
        """Format vulnerability findings"""
        
        findings = []
        
        for vuln in state["vulnerabilities"]:
            finding = {
                "id": vuln.get("vulnerability_id", "N/A"),
                "type": vuln["type"],
                "severity": vuln["severity"],
                "location": vuln["location"],
                "description": vuln["description"],
                "evidence": vuln["evidence"],
                "exploitation_status": vuln["exploitation_status"],
                "remediation": self._get_remediation(vuln["type"])
            }
            findings.append(finding)
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings.sort(key=lambda x: severity_order.get(x["severity"], 999))
        
        return findings
    
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
                e.get("execution_time", 0) for e in state["execution_history"]
            ),
            "total_scans": len(state["execution_history"])
        }
    
    def _generate_statistics(self, state: dict) -> Dict[str, Any]:
        """Generate testing statistics"""
        
        return {
            "total_loops": state["loop_count"],
            "total_executions": state["total_executions"],
            "successful_executions": len([e for e in state["execution_history"] 
                                         if e["return_code"] == 0]),
            "failed_executions": len([e for e in state["execution_history"] 
                                     if e["return_code"] != 0]),
            "reflections_performed": len(state["reflections"]),
            "average_reflection_confidence": (
                sum(r["confidence"] for r in state["reflections"]) / len(state["reflections"])
                if state["reflections"] else 0
            )
        }
    
    def _generate_recommendations(self, state: dict) -> List[Dict[str, str]]:
        """Generate remediation recommendations"""
        
        recommendations = []
        
        # Critical vulnerabilities need immediate action
        critical = [v for v in state["vulnerabilities"] if v["severity"] == "critical"]
        if critical:
            recommendations.append({
                "priority": "CRITICAL",
                "action": "Immediately address all critical vulnerabilities",
                "rationale": "Critical vulnerabilities pose immediate risk of system compromise"
            })
        
        # SQL injection
        if any(v["type"] == "sql_injection" for v in state["vulnerabilities"]):
            recommendations.append({
                "priority": "HIGH",
                "action": "Implement parameterized queries and input validation",
                "rationale": "SQL injection allows unauthorized database access"
            })
        
        # Weak credentials
        if any(v["type"] == "weak_credentials" for v in state["vulnerabilities"]):
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
    
    def _generate_appendix(self, state: dict) -> Dict[str, Any]:
        """Generate technical appendix with execution details"""
        
        return {
            "execution_log": [
                {
                    "tool": e["tool_name"],
                    "status": e["status"].value,
                    "time": e["execution_time"],
                    "args": str(e["tool_args"])
                }
                for e in state["execution_history"][:20]  # Last 20 executions
            ],
            "errors_encountered": state["errors"],
            "warnings": state["warnings"]
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
        
        return remediations.get(vulnerability_type, "Address this vulnerability per security best practices")
