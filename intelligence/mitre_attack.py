"""
MITRE ATT&CK Framework Mapping
==============================

Maps RedAgent findings and attacks to the MITRE ATT&CK framework
for professional, standardized reporting.

Reference: https://attack.mitre.org/
"""

import logging
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class TacticID(Enum):
    """MITRE ATT&CK Tactics"""
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


@dataclass
class MitreTechnique:
    """MITRE ATT&CK Technique"""
    id: str
    name: str
    tactic: TacticID
    description: str
    detection: str
    mitigation: str
    url: str = ""
    sub_techniques: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        self.url = f"https://attack.mitre.org/techniques/{self.id.replace('.', '/')}/"


@dataclass
class AttackMapping:
    """Mapping of a finding to MITRE ATT&CK"""
    finding_type: str
    technique: MitreTechnique
    confidence: float  # 0.0 - 1.0
    evidence: str
    timestamp: str = ""


class MitreAttackMapper:
    """
    Maps security findings to MITRE ATT&CK framework.
    
    Provides:
    - Automatic technique identification
    - Tactic chain visualization
    - Professional reporting format
    - Detection and mitigation guidance
    """
    
    def __init__(self):
        self.techniques = self._load_technique_database()
        self.finding_mappings = self._load_finding_mappings()
        
        logger.info(f"MITRE ATT&CK Mapper initialized with {len(self.techniques)} techniques")
    
    def _load_technique_database(self) -> Dict[str, MitreTechnique]:
        """Load MITRE ATT&CK technique database"""
        techniques = {}
        
        # Reconnaissance
        techniques["T1595"] = MitreTechnique(
            id="T1595",
            name="Active Scanning",
            tactic=TacticID.RECONNAISSANCE,
            description="Adversaries may scan victim IP blocks to gather information for targeting.",
            detection="Monitor for suspicious network scanning activity",
            mitigation="Implement network intrusion detection systems"
        )
        techniques["T1595.001"] = MitreTechnique(
            id="T1595.001",
            name="Scanning IP Blocks",
            tactic=TacticID.RECONNAISSANCE,
            description="Adversaries may scan victim IP blocks to gather information.",
            detection="Monitor for sequential or distributed port scanning",
            mitigation="Use network firewalls to limit scanning"
        )
        techniques["T1595.002"] = MitreTechnique(
            id="T1595.002",
            name="Vulnerability Scanning",
            tactic=TacticID.RECONNAISSANCE,
            description="Adversaries may scan for vulnerabilities in victim systems.",
            detection="Monitor for vulnerability scanner signatures",
            mitigation="Keep systems patched and updated"
        )
        techniques["T1592"] = MitreTechnique(
            id="T1592",
            name="Gather Victim Host Information",
            tactic=TacticID.RECONNAISSANCE,
            description="Adversaries may gather information about victim hosts.",
            detection="Monitor for information gathering attempts",
            mitigation="Minimize publicly available system information"
        )
        techniques["T1589"] = MitreTechnique(
            id="T1589",
            name="Gather Victim Identity Information",
            tactic=TacticID.RECONNAISSANCE,
            description="Adversaries may gather information about victim identities.",
            detection="Monitor for OSINT gathering activities",
            mitigation="Limit employee information exposure"
        )
        
        # Initial Access
        techniques["T1190"] = MitreTechnique(
            id="T1190",
            name="Exploit Public-Facing Application",
            tactic=TacticID.INITIAL_ACCESS,
            description="Adversaries may exploit vulnerabilities in Internet-facing applications.",
            detection="Monitor web server logs for exploitation attempts",
            mitigation="Keep applications updated, use WAF"
        )
        techniques["T1133"] = MitreTechnique(
            id="T1133",
            name="External Remote Services",
            tactic=TacticID.INITIAL_ACCESS,
            description="Adversaries may leverage external remote services for initial access.",
            detection="Monitor authentication logs for remote access services",
            mitigation="Use MFA, limit remote access exposure"
        )
        techniques["T1078"] = MitreTechnique(
            id="T1078",
            name="Valid Accounts",
            tactic=TacticID.INITIAL_ACCESS,
            description="Adversaries may obtain and abuse credentials of existing accounts.",
            detection="Monitor for unusual account activity",
            mitigation="Implement strong password policies, MFA"
        )
        
        # Execution
        techniques["T1059"] = MitreTechnique(
            id="T1059",
            name="Command and Scripting Interpreter",
            tactic=TacticID.EXECUTION,
            description="Adversaries may abuse command interpreters to execute commands.",
            detection="Monitor process command-line arguments",
            mitigation="Disable unnecessary scripting interpreters"
        )
        techniques["T1059.001"] = MitreTechnique(
            id="T1059.001",
            name="PowerShell",
            tactic=TacticID.EXECUTION,
            description="Adversaries may abuse PowerShell for execution.",
            detection="Enable PowerShell logging, monitor for suspicious scripts",
            mitigation="Use constrained language mode, code signing"
        )
        techniques["T1203"] = MitreTechnique(
            id="T1203",
            name="Exploitation for Client Execution",
            tactic=TacticID.EXECUTION,
            description="Adversaries may exploit client applications for execution.",
            detection="Monitor for application crashes, unusual behavior",
            mitigation="Keep applications updated, use application whitelisting"
        )
        
        # Credential Access
        techniques["T1110"] = MitreTechnique(
            id="T1110",
            name="Brute Force",
            tactic=TacticID.CREDENTIAL_ACCESS,
            description="Adversaries may use brute force techniques to gain access.",
            detection="Monitor for multiple failed authentication attempts",
            mitigation="Implement account lockout policies, MFA"
        )
        techniques["T1110.001"] = MitreTechnique(
            id="T1110.001",
            name="Password Guessing",
            tactic=TacticID.CREDENTIAL_ACCESS,
            description="Adversaries may guess passwords to attempt access.",
            detection="Monitor for password spray patterns",
            mitigation="Enforce strong password policies"
        )
        techniques["T1110.003"] = MitreTechnique(
            id="T1110.003",
            name="Password Spraying",
            tactic=TacticID.CREDENTIAL_ACCESS,
            description="Adversaries may use password spraying against many accounts.",
            detection="Monitor for distributed authentication failures",
            mitigation="Implement smart lockout, MFA"
        )
        techniques["T1552"] = MitreTechnique(
            id="T1552",
            name="Unsecured Credentials",
            tactic=TacticID.CREDENTIAL_ACCESS,
            description="Adversaries may search for unsecured credentials.",
            detection="Monitor for credential access patterns",
            mitigation="Use credential management solutions, encrypt credentials"
        )
        
        # Discovery
        techniques["T1046"] = MitreTechnique(
            id="T1046",
            name="Network Service Discovery",
            tactic=TacticID.DISCOVERY,
            description="Adversaries may scan for services running on remote hosts.",
            detection="Monitor for port scanning activity",
            mitigation="Segment networks, use firewalls"
        )
        techniques["T1087"] = MitreTechnique(
            id="T1087",
            name="Account Discovery",
            tactic=TacticID.DISCOVERY,
            description="Adversaries may attempt to get account names and information.",
            detection="Monitor for account enumeration attempts",
            mitigation="Limit account information exposure"
        )
        
        # Defense Evasion
        techniques["T1027"] = MitreTechnique(
            id="T1027",
            name="Obfuscated Files or Information",
            tactic=TacticID.DEFENSE_EVASION,
            description="Adversaries may obfuscate payloads to evade detection.",
            detection="Use behavioral analysis, deobfuscation tools",
            mitigation="Implement content inspection"
        )
        techniques["T1562"] = MitreTechnique(
            id="T1562",
            name="Impair Defenses",
            tactic=TacticID.DEFENSE_EVASION,
            description="Adversaries may disable security tools.",
            detection="Monitor for security tool tampering",
            mitigation="Protect security tool configurations"
        )
        
        # Collection
        techniques["T1005"] = MitreTechnique(
            id="T1005",
            name="Data from Local System",
            tactic=TacticID.COLLECTION,
            description="Adversaries may collect data from local system sources.",
            detection="Monitor for sensitive file access",
            mitigation="Implement DLP, encryption"
        )
        techniques["T1213"] = MitreTechnique(
            id="T1213",
            name="Data from Information Repositories",
            tactic=TacticID.COLLECTION,
            description="Adversaries may collect data from information repositories.",
            detection="Monitor database and repo access",
            mitigation="Implement access controls, audit logging"
        )
        
        # Impact
        techniques["T1485"] = MitreTechnique(
            id="T1485",
            name="Data Destruction",
            tactic=TacticID.IMPACT,
            description="Adversaries may destroy data and files.",
            detection="Monitor for mass file deletions",
            mitigation="Implement backups, access controls"
        )
        techniques["T1486"] = MitreTechnique(
            id="T1486",
            name="Data Encrypted for Impact",
            tactic=TacticID.IMPACT,
            description="Adversaries may encrypt data for impact (ransomware).",
            detection="Monitor for encryption activity",
            mitigation="Implement backups, endpoint protection"
        )
        
        return techniques
    
    def _load_finding_mappings(self) -> Dict[str, List[str]]:
        """Map finding types to MITRE technique IDs"""
        return {
            # Vulnerability types -> Techniques
            "sql_injection": ["T1190", "T1213"],
            "xss": ["T1190", "T1059"],
            "command_injection": ["T1190", "T1059"],
            "path_traversal": ["T1190", "T1005"],
            "ssrf": ["T1190"],
            "xxe": ["T1190", "T1005"],
            "ldap_injection": ["T1190", "T1087"],
            "brute_force": ["T1110", "T1110.001", "T1110.003"],
            "weak_credentials": ["T1078", "T1110"],
            "authentication_bypass": ["T1078"],
            
            # Reconnaissance findings
            "port_scan": ["T1595", "T1595.001", "T1046"],
            "vulnerability_scan": ["T1595.002"],
            "subdomain_enum": ["T1592"],
            "osint_gathering": ["T1589", "T1592"],
            "technology_fingerprint": ["T1592"],
            
            # Exposure findings
            "exposed_database": ["T1213", "T1190"],
            "exposed_remote_access": ["T1133"],
            "exposed_admin_panel": ["T1190", "T1078"],
            "missing_security_headers": ["T1190"],
            "information_disclosure": ["T1592"],
            
            # Attack execution
            "remote_code_execution": ["T1059", "T1203"],
            "privilege_escalation": ["T1078"],
            "data_exfiltration": ["T1005", "T1213"],
            "waf_bypass": ["T1562", "T1027"],
        }
    
    def map_finding(self, finding: Dict[str, Any]) -> List[AttackMapping]:
        """Map a single finding to MITRE ATT&CK techniques"""
        mappings = []
        
        finding_type = finding.get("type", "").lower().replace(" ", "_")
        technique_ids = self.finding_mappings.get(finding_type, [])
        
        # Also check subtype
        subtype = finding.get("subtype", "").lower().replace(" ", "_")
        technique_ids.extend(self.finding_mappings.get(subtype, []))
        
        # Deduplicate
        technique_ids = list(set(technique_ids))
        
        for tech_id in technique_ids:
            technique = self.techniques.get(tech_id)
            if technique:
                confidence = self._calculate_confidence(finding, technique)
                mappings.append(AttackMapping(
                    finding_type=finding_type,
                    technique=technique,
                    confidence=confidence,
                    evidence=finding.get("evidence", ""),
                    timestamp=finding.get("timestamp", "")
                ))
        
        return mappings
    
    def map_findings(self, findings: List[Dict]) -> Dict[str, Any]:
        """Map multiple findings to MITRE ATT&CK"""
        result = {
            "total_findings": len(findings),
            "mapped_findings": 0,
            "techniques_identified": [],
            "tactics_covered": [],
            "attack_chain": [],
            "mappings": []
        }
        
        all_tactics = set()
        all_techniques = set()
        
        for finding in findings:
            mappings = self.map_finding(finding)
            
            if mappings:
                result["mapped_findings"] += 1
                
                for mapping in mappings:
                    all_techniques.add(mapping.technique.id)
                    all_tactics.add(mapping.technique.tactic.value)
                    
                    result["mappings"].append({
                        "finding_type": mapping.finding_type,
                        "technique_id": mapping.technique.id,
                        "technique_name": mapping.technique.name,
                        "tactic": mapping.technique.tactic.name,
                        "confidence": mapping.confidence,
                        "url": mapping.technique.url,
                        "detection": mapping.technique.detection,
                        "mitigation": mapping.technique.mitigation
                    })
        
        result["techniques_identified"] = list(all_techniques)
        result["tactics_covered"] = list(all_tactics)
        result["attack_chain"] = self._build_attack_chain(list(all_tactics))
        
        return result
    
    def _calculate_confidence(self, finding: Dict, technique: MitreTechnique) -> float:
        """Calculate mapping confidence based on evidence"""
        confidence = 0.5  # Base confidence
        
        # Increase for confirmed exploitation
        if finding.get("exploitation_status") == "confirmed":
            confidence += 0.3
        elif finding.get("exploitation_status") == "potential":
            confidence += 0.1
        
        # Increase for high/critical severity
        severity = finding.get("severity", "").lower()
        if severity == "critical":
            confidence += 0.15
        elif severity == "high":
            confidence += 0.1
        
        # Increase if evidence is present
        if finding.get("evidence"):
            confidence += 0.05
        
        return min(confidence, 1.0)
    
    def _build_attack_chain(self, tactics: List[str]) -> List[Dict]:
        """Build attack chain from identified tactics"""
        # MITRE ATT&CK tactic order
        tactic_order = [
            ("TA0043", "Reconnaissance"),
            ("TA0042", "Resource Development"),
            ("TA0001", "Initial Access"),
            ("TA0002", "Execution"),
            ("TA0003", "Persistence"),
            ("TA0004", "Privilege Escalation"),
            ("TA0005", "Defense Evasion"),
            ("TA0006", "Credential Access"),
            ("TA0007", "Discovery"),
            ("TA0008", "Lateral Movement"),
            ("TA0009", "Collection"),
            ("TA0011", "Command and Control"),
            ("TA0010", "Exfiltration"),
            ("TA0040", "Impact"),
        ]
        
        chain = []
        for tactic_id, tactic_name in tactic_order:
            chain.append({
                "id": tactic_id,
                "name": tactic_name,
                "covered": tactic_id in tactics,
                "order": len(chain) + 1
            })
        
        return chain
    
    def get_technique(self, technique_id: str) -> Optional[MitreTechnique]:
        """Get technique by ID"""
        return self.techniques.get(technique_id)
    
    def get_techniques_by_tactic(self, tactic: TacticID) -> List[MitreTechnique]:
        """Get all techniques for a tactic"""
        return [t for t in self.techniques.values() if t.tactic == tactic]
    
    def generate_attack_navigator_layer(self, mappings: Dict) -> Dict:
        """Generate MITRE ATT&CK Navigator layer JSON"""
        layer = {
            "name": "RedAgent Assessment",
            "versions": {
                "attack": "14",
                "navigator": "4.9.1",
                "layer": "4.5"
            },
            "domain": "enterprise-attack",
            "description": "Techniques identified by RedAgent security assessment",
            "techniques": []
        }
        
        for mapping in mappings.get("mappings", []):
            layer["techniques"].append({
                "techniqueID": mapping["technique_id"],
                "tactic": mapping["tactic"].lower().replace("_", "-"),
                "score": int(mapping["confidence"] * 100),
                "color": self._get_score_color(mapping["confidence"]),
                "comment": f"Finding: {mapping['finding_type']}"
            })
        
        return layer
    
    def _get_score_color(self, confidence: float) -> str:
        """Get color based on confidence score"""
        if confidence >= 0.8:
            return "#ff0000"  # Red - high confidence
        elif confidence >= 0.6:
            return "#ff6600"  # Orange
        elif confidence >= 0.4:
            return "#ffcc00"  # Yellow
        else:
            return "#99cc00"  # Light green


# Singleton instance
_mitre_mapper: Optional[MitreAttackMapper] = None

def get_mitre_mapper() -> MitreAttackMapper:
    """Get or create MITRE mapper singleton"""
    global _mitre_mapper
    if _mitre_mapper is None:
        _mitre_mapper = MitreAttackMapper()
    return _mitre_mapper
