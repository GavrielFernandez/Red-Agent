"""
Nuclei Scanner Integration
===========================

Enterprise-grade integration with ProjectDiscovery's Nuclei scanner
for template-based vulnerability scanning.

Features:
- Custom template management
- Parallel scanning orchestration
- Result parsing and normalization
- Integration with RedAgent findings
"""

import os
import json
import yaml
import asyncio
import logging
import subprocess
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class TemplateSeverity(Enum):
    """Nuclei template severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class TemplateType(Enum):
    """Nuclei template categories"""
    CVE = "cves"
    VULNERABILITIES = "vulnerabilities"
    MISCONFIGURATIONS = "misconfigurations"
    EXPOSURES = "exposures"
    TECHNOLOGIES = "technologies"
    WORKFLOWS = "workflows"
    HEADLESS = "headless"
    FUZZING = "fuzzing"
    DEFAULT_LOGINS = "default-logins"
    TAKEOVERS = "takeovers"


@dataclass
class NucleiResult:
    """Single Nuclei scan result"""
    template_id: str
    template_name: str
    severity: TemplateSeverity
    host: str
    matched_at: str
    timestamp: str
    description: str = ""
    matcher_name: str = ""
    extracted_results: List[str] = field(default_factory=list)
    curl_command: str = ""
    request: str = ""
    response: str = ""
    cve_id: str = ""
    cvss_score: float = 0.0
    cvss_metrics: str = ""
    cwe_id: str = ""
    reference: List[str] = field(default_factory=list)


@dataclass
class ScanConfig:
    """Nuclei scan configuration"""
    targets: List[str]
    templates: List[str] = field(default_factory=list)
    template_tags: List[str] = field(default_factory=list)
    severity_filter: List[TemplateSeverity] = field(default_factory=list)
    rate_limit: int = 150
    bulk_size: int = 25
    concurrency: int = 25
    timeout: int = 10
    retries: int = 1
    exclude_tags: List[str] = field(default_factory=list)
    headless: bool = False
    interactsh: bool = True


class NucleiScanner:
    """
    Nuclei vulnerability scanner integration.
    
    Provides:
    - Automated scanning with 1000s of templates
    - CVE detection
    - Custom template support
    - OAST (Out-of-band testing) via Interactsh
    """
    
    def __init__(self, nuclei_path: str = "nuclei"):
        self.nuclei_path = nuclei_path
        self.custom_templates_dir = Path("templates/nuclei")
        self.results_dir = Path("logs/nuclei_scans")
        self.is_available = self._check_nuclei_available()
        
        # Create directories
        self.custom_templates_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        # Built-in custom templates
        self._create_custom_templates()
        
        logger.info(f"Nuclei Scanner initialized (available: {self.is_available})")
    
    def _check_nuclei_available(self) -> bool:
        """Check if Nuclei is installed and available"""
        try:
            result = subprocess.run(
                [self.nuclei_path, "-version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info(f"Nuclei available: {result.stdout.strip()}")
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            logger.warning(f"Nuclei not available: {e}")
        return False
    
    def _create_custom_templates(self):
        """Create RedAgent custom templates"""
        templates = {
            "redagent-headers.yaml": self._template_security_headers(),
            "redagent-sqli.yaml": self._template_sqli_detection(),
            "redagent-xss.yaml": self._template_xss_detection(),
            "redagent-lfi.yaml": self._template_lfi_detection(),
            "redagent-rce.yaml": self._template_rce_detection(),
            "redagent-ssrf.yaml": self._template_ssrf_detection(),
            "redagent-api.yaml": self._template_api_security(),
        }
        
        for name, content in templates.items():
            template_path = self.custom_templates_dir / name
            if not template_path.exists():
                with open(template_path, 'w') as f:
                    yaml.dump(content, f, default_flow_style=False)
                logger.debug(f"Created custom template: {name}")
    
    def _template_security_headers(self) -> Dict:
        """Security headers detection template"""
        return {
            "id": "redagent-missing-security-headers",
            "info": {
                "name": "Missing Security Headers",
                "author": "RedAgent",
                "severity": "info",
                "description": "Detects missing security headers",
                "tags": ["misconfig", "headers", "redagent"]
            },
            "requests": [{
                "method": "GET",
                "path": ["/"],
                "matchers-condition": "or",
                "matchers": [
                    {
                        "type": "regex",
                        "part": "header",
                        "negative": True,
                        "regex": ["(?i)x-frame-options"]
                    },
                    {
                        "type": "regex",
                        "part": "header",
                        "negative": True,
                        "regex": ["(?i)content-security-policy"]
                    },
                    {
                        "type": "regex",
                        "part": "header",
                        "negative": True,
                        "regex": ["(?i)strict-transport-security"]
                    }
                ]
            }]
        }
    
    def _template_sqli_detection(self) -> Dict:
        """SQL injection detection template"""
        return {
            "id": "redagent-sqli-detection",
            "info": {
                "name": "SQL Injection Detection",
                "author": "RedAgent",
                "severity": "critical",
                "description": "Detects potential SQL injection vulnerabilities",
                "tags": ["sqli", "injection", "redagent"]
            },
            "requests": [{
                "method": "GET",
                "path": [
                    "/?id=1'",
                    "/?id=1\"",
                    "/?id=1 AND 1=1",
                    "/?search=test' OR '1'='1"
                ],
                "matchers-condition": "or",
                "matchers": [
                    {
                        "type": "word",
                        "words": [
                            "SQL syntax",
                            "mysql_fetch",
                            "ORA-",
                            "PostgreSQL",
                            "SQLITE_ERROR",
                            "Microsoft SQL",
                            "syntax error"
                        ]
                    },
                    {
                        "type": "regex",
                        "regex": [
                            "(?i)you have an error in your sql syntax",
                            "(?i)unclosed quotation mark",
                            "(?i)quoted string not properly terminated"
                        ]
                    }
                ]
            }]
        }
    
    def _template_xss_detection(self) -> Dict:
        """XSS detection template"""
        return {
            "id": "redagent-xss-detection",
            "info": {
                "name": "XSS Detection",
                "author": "RedAgent",
                "severity": "high",
                "description": "Detects potential cross-site scripting vulnerabilities",
                "tags": ["xss", "injection", "redagent"]
            },
            "requests": [{
                "method": "GET",
                "path": [
                    "/?q=<script>alert(1)</script>",
                    "/?search=<img src=x onerror=alert(1)>",
                    "/?name=<svg/onload=alert(1)>"
                ],
                "matchers": [{
                    "type": "word",
                    "part": "body",
                    "words": [
                        "<script>alert(1)</script>",
                        "<img src=x onerror=alert(1)>",
                        "<svg/onload=alert(1)>"
                    ]
                }]
            }]
        }
    
    def _template_lfi_detection(self) -> Dict:
        """Local File Inclusion detection template"""
        return {
            "id": "redagent-lfi-detection",
            "info": {
                "name": "LFI Detection",
                "author": "RedAgent",
                "severity": "high",
                "description": "Detects local file inclusion vulnerabilities",
                "tags": ["lfi", "inclusion", "redagent"]
            },
            "requests": [{
                "method": "GET",
                "path": [
                    "/?file=../../../etc/passwd",
                    "/?page=....//....//....//etc/passwd",
                    "/?path=/etc/passwd%00"
                ],
                "matchers": [{
                    "type": "regex",
                    "regex": [
                        "root:.*:0:0:",
                        "daemon:.*:/usr/sbin"
                    ]
                }]
            }]
        }
    
    def _template_rce_detection(self) -> Dict:
        """Remote Code Execution detection template"""
        return {
            "id": "redagent-rce-detection",
            "info": {
                "name": "RCE Detection",
                "author": "RedAgent",
                "severity": "critical",
                "description": "Detects remote code execution vulnerabilities",
                "tags": ["rce", "injection", "redagent"]
            },
            "requests": [{
                "method": "GET",
                "path": [
                    "/?cmd=id",
                    "/?exec=whoami",
                    "/?command=cat /etc/passwd"
                ],
                "matchers": [{
                    "type": "regex",
                    "regex": [
                        "uid=[0-9]+.*gid=[0-9]+",
                        "root:x:0:0:"
                    ]
                }]
            }]
        }
    
    def _template_ssrf_detection(self) -> Dict:
        """SSRF detection template"""
        return {
            "id": "redagent-ssrf-detection",
            "info": {
                "name": "SSRF Detection",
                "author": "RedAgent",
                "severity": "high",
                "description": "Detects server-side request forgery vulnerabilities",
                "tags": ["ssrf", "redagent"]
            },
            "requests": [{
                "method": "GET",
                "path": [
                    "/?url=http://127.0.0.1",
                    "/?fetch=http://localhost",
                    "/?redirect=http://169.254.169.254"
                ],
                "matchers-condition": "or",
                "matchers": [
                    {
                        "type": "word",
                        "words": [
                            "localhost",
                            "127.0.0.1",
                            "meta-data"
                        ]
                    }
                ]
            }]
        }
    
    def _template_api_security(self) -> Dict:
        """API security template"""
        return {
            "id": "redagent-api-security",
            "info": {
                "name": "API Security Check",
                "author": "RedAgent",
                "severity": "medium",
                "description": "Checks for common API security issues",
                "tags": ["api", "security", "redagent"]
            },
            "requests": [{
                "method": "GET",
                "path": [
                    "/api/",
                    "/api/v1/",
                    "/api/v2/",
                    "/swagger.json",
                    "/openapi.json",
                    "/api-docs"
                ],
                "matchers": [{
                    "type": "status",
                    "status": [200]
                }]
            }]
        }
    
    async def scan(self, config: ScanConfig) -> List[NucleiResult]:
        """Execute Nuclei scan"""
        if not self.is_available:
            logger.error("Nuclei not available, skipping scan")
            return []
        
        cmd = self._build_command(config)
        output_file = self.results_dir / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        cmd.extend(["-json", "-o", str(output_file)])
        
        logger.info(f"Starting Nuclei scan: {' '.join(cmd)}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=config.timeout * 60  # Minutes to seconds
            )
            
            if process.returncode != 0:
                logger.warning(f"Nuclei scan completed with warnings: {stderr.decode()}")
            
            return self._parse_results(output_file)
            
        except asyncio.TimeoutError:
            logger.error("Nuclei scan timed out")
            return []
        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}")
            return []
    
    def scan_sync(self, config: ScanConfig) -> List[NucleiResult]:
        """Synchronous scan execution"""
        if not self.is_available:
            logger.error("Nuclei not available")
            return []
        
        cmd = self._build_command(config)
        output_file = self.results_dir / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        cmd.extend(["-json", "-o", str(output_file)])
        
        logger.info(f"Starting Nuclei scan (sync): {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.timeout * 60
            )
            
            if result.returncode != 0:
                logger.warning(f"Nuclei scan warnings: {result.stderr}")
            
            return self._parse_results(output_file)
            
        except subprocess.TimeoutExpired:
            logger.error("Nuclei scan timed out")
            return []
        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}")
            return []
    
    def _build_command(self, config: ScanConfig) -> List[str]:
        """Build Nuclei command line"""
        cmd = [self.nuclei_path]
        
        # Targets
        if len(config.targets) == 1:
            cmd.extend(["-target", config.targets[0]])
        else:
            # Write targets to temp file
            targets_file = self.results_dir / "targets.txt"
            with open(targets_file, 'w') as f:
                f.write("\n".join(config.targets))
            cmd.extend(["-list", str(targets_file)])
        
        # Templates
        if config.templates:
            for template in config.templates:
                cmd.extend(["-t", template])
        
        # Custom templates
        if self.custom_templates_dir.exists():
            cmd.extend(["-t", str(self.custom_templates_dir)])
        
        # Template tags
        if config.template_tags:
            cmd.extend(["-tags", ",".join(config.template_tags)])
        
        # Severity filter
        if config.severity_filter:
            severities = [s.value for s in config.severity_filter]
            cmd.extend(["-severity", ",".join(severities)])
        
        # Exclude tags
        if config.exclude_tags:
            cmd.extend(["-exclude-tags", ",".join(config.exclude_tags)])
        
        # Rate limiting
        cmd.extend(["-rate-limit", str(config.rate_limit)])
        cmd.extend(["-bulk-size", str(config.bulk_size)])
        cmd.extend(["-concurrency", str(config.concurrency)])
        
        # Timeout and retries
        cmd.extend(["-timeout", str(config.timeout)])
        cmd.extend(["-retries", str(config.retries)])
        
        # Headless mode
        if config.headless:
            cmd.append("-headless")
        
        # Interactsh
        if not config.interactsh:
            cmd.append("-no-interactsh")
        
        # Additional flags
        cmd.append("-silent")
        cmd.append("-no-color")
        
        return cmd
    
    def _parse_results(self, output_file: Path) -> List[NucleiResult]:
        """Parse Nuclei JSON output"""
        results = []
        
        if not output_file.exists():
            logger.warning(f"Output file not found: {output_file}")
            return results
        
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            data = json.loads(line)
                            result = self._parse_single_result(data)
                            if result:
                                results.append(result)
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            logger.error(f"Failed to parse results: {e}")
        
        logger.info(f"Parsed {len(results)} results from Nuclei scan")
        return results
    
    def _parse_single_result(self, data: Dict) -> Optional[NucleiResult]:
        """Parse single Nuclei JSON result"""
        try:
            info = data.get("info", {})
            
            # Parse severity
            severity_str = info.get("severity", "unknown").lower()
            try:
                severity = TemplateSeverity(severity_str)
            except ValueError:
                severity = TemplateSeverity.UNKNOWN
            
            # Parse classification
            classification = info.get("classification", {})
            
            return NucleiResult(
                template_id=data.get("template-id", ""),
                template_name=info.get("name", ""),
                severity=severity,
                host=data.get("host", ""),
                matched_at=data.get("matched-at", ""),
                timestamp=data.get("timestamp", ""),
                description=info.get("description", ""),
                matcher_name=data.get("matcher-name", ""),
                extracted_results=data.get("extracted-results", []),
                curl_command=data.get("curl-command", ""),
                request=data.get("request", ""),
                response=data.get("response", ""),
                cve_id=classification.get("cve-id", ""),
                cvss_score=float(classification.get("cvss-score", 0)),
                cvss_metrics=classification.get("cvss-metrics", ""),
                cwe_id=str(classification.get("cwe-id", "")),
                reference=info.get("reference", [])
            )
        except Exception as e:
            logger.warning(f"Failed to parse result: {e}")
            return None
    
    def convert_to_findings(self, results: List[NucleiResult]) -> List[Dict]:
        """Convert Nuclei results to RedAgent findings format"""
        findings = []
        
        for result in results:
            finding = {
                "type": self._map_template_to_type(result.template_id),
                "subtype": result.template_name,
                "severity": result.severity.value,
                "target": result.host,
                "evidence": result.matched_at,
                "description": result.description,
                "source": "nuclei",
                "template_id": result.template_id,
                "timestamp": result.timestamp,
                "references": result.reference
            }
            
            # Add CVE info if available
            if result.cve_id:
                finding["cve_id"] = result.cve_id
                finding["cvss_score"] = result.cvss_score
                finding["cvss_metrics"] = result.cvss_metrics
            
            if result.cwe_id:
                finding["cwe_id"] = result.cwe_id
            
            findings.append(finding)
        
        return findings
    
    def _map_template_to_type(self, template_id: str) -> str:
        """Map Nuclei template ID to finding type"""
        template_lower = template_id.lower()
        
        if "sqli" in template_lower or "sql-injection" in template_lower:
            return "sql_injection"
        elif "xss" in template_lower:
            return "xss"
        elif "rce" in template_lower or "command-injection" in template_lower:
            return "command_injection"
        elif "lfi" in template_lower or "path-traversal" in template_lower:
            return "path_traversal"
        elif "ssrf" in template_lower:
            return "ssrf"
        elif "xxe" in template_lower:
            return "xxe"
        elif "cve-" in template_lower:
            return "cve_vulnerability"
        elif "takeover" in template_lower:
            return "subdomain_takeover"
        elif "exposure" in template_lower:
            return "information_disclosure"
        elif "misconfig" in template_lower:
            return "misconfiguration"
        elif "default-login" in template_lower:
            return "weak_credentials"
        else:
            return "vulnerability_scan"
    
    def get_statistics(self, results: List[NucleiResult]) -> Dict:
        """Get scan statistics"""
        stats = {
            "total_findings": len(results),
            "by_severity": {},
            "by_host": {},
            "by_template": {},
            "cve_count": 0,
            "unique_hosts": set(),
            "unique_templates": set()
        }
        
        for result in results:
            # By severity
            severity = result.severity.value
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
            
            # By host
            stats["by_host"][result.host] = stats["by_host"].get(result.host, 0) + 1
            stats["unique_hosts"].add(result.host)
            
            # By template
            stats["by_template"][result.template_id] = stats["by_template"].get(result.template_id, 0) + 1
            stats["unique_templates"].add(result.template_id)
            
            # CVE count
            if result.cve_id:
                stats["cve_count"] += 1
        
        stats["unique_hosts"] = len(stats["unique_hosts"])
        stats["unique_templates"] = len(stats["unique_templates"])
        
        return stats


# Singleton
_nuclei_scanner: Optional[NucleiScanner] = None

def get_nuclei_scanner() -> NucleiScanner:
    """Get or create Nuclei scanner singleton"""
    global _nuclei_scanner
    if _nuclei_scanner is None:
        _nuclei_scanner = NucleiScanner()
    return _nuclei_scanner
