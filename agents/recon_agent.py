"""
Reconnaissance Agent - OSINT & Asset Discovery Specialist
==========================================================

Specialized agent for:
- OSINT gathering (Shodan, Censys, etc.)
- Subdomain enumeration
- Technology fingerprinting
- Port scanning coordination
- Cloud asset discovery
- Social engineering intel
"""

import asyncio
import logging
import re
import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import socket

from .base_agent import BaseAgent, AgentCapability, TaskResult, MessageType, Priority, AgentMessage

logger = logging.getLogger(__name__)


class ReconAgent(BaseAgent):
    """
    Reconnaissance Agent - The eyes of the operation
    
    Specializes in gathering intelligence about targets before exploitation.
    Integrates with multiple OSINT sources.
    """
    
    def __init__(self, llm_client: Any = None, osint_config: Optional[Dict] = None, **kwargs):
        super().__init__(
            name="ReconAgent",
            llm_client=llm_client,
            **kwargs
        )
        
        # OSINT API configuration
        self.osint_config = osint_config or {}
        self.api_keys = {
            "shodan": self.osint_config.get("SHODAN_API_KEY", ""),
            "censys_id": self.osint_config.get("CENSYS_API_ID", ""),
            "censys_secret": self.osint_config.get("CENSYS_API_SECRET", ""),
            "virustotal": self.osint_config.get("VIRUSTOTAL_API_KEY", ""),
            "securitytrails": self.osint_config.get("SECURITYTRAILS_API_KEY", ""),
            "hunter": self.osint_config.get("HUNTER_API_KEY", ""),
        }
        
        # Discovered assets
        self.discovered_subdomains: List[str] = []
        self.discovered_ips: List[str] = []
        self.discovered_ports: Dict[str, List[int]] = {}
        self.tech_stack: Dict[str, Any] = {}
        self.employees: List[Dict] = []
        self.leaked_credentials: List[Dict] = []
        
        logger.info(f"ReconAgent initialized with OSINT sources: {[k for k, v in self.api_keys.items() if v]}")
    
    @property
    def capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="reconnaissance",
                description="Full reconnaissance and asset discovery",
                input_types=["target", "domain", "ip"],
                output_types=["intel", "assets", "subdomains"]
            ),
            AgentCapability(
                name="osint",
                description="Open source intelligence gathering",
                input_types=["domain", "ip", "email"],
                output_types=["intel", "leaked_data", "social"]
            ),
            AgentCapability(
                name="subdomain_enum",
                description="Subdomain enumeration",
                input_types=["domain"],
                output_types=["subdomains"]
            ),
            AgentCapability(
                name="tech_fingerprint",
                description="Technology stack fingerprinting",
                input_types=["url"],
                output_types=["technologies"]
            ),
            AgentCapability(
                name="port_scan",
                description="Port scanning coordination",
                input_types=["ip", "domain"],
                output_types=["open_ports", "services"]
            )
        ]
    
    async def execute_task(self, task: Dict[str, Any]) -> TaskResult:
        """Execute recon tasks"""
        task_type = task.get("type", "")
        target = task.get("target", "")
        
        if not target:
            return TaskResult(
                task_id=task.get("id", ""),
                success=False,
                error="No target specified"
            )
        
        try:
            if task_type == "full_recon":
                return await self._full_recon(task)
            elif task_type == "subdomain_enum":
                return await self._enumerate_subdomains(task)
            elif task_type == "osint_gather":
                return await self._gather_osint(task)
            elif task_type == "port_scan":
                return await self._coordinate_port_scan(task)
            elif task_type == "tech_fingerprint":
                return await self._fingerprint_tech(task)
            else:
                return TaskResult(
                    task_id=task.get("id", ""),
                    success=False,
                    error=f"Unknown task type: {task_type}"
                )
        except Exception as e:
            logger.error(f"ReconAgent task failed: {e}")
            return TaskResult(
                task_id=task.get("id", ""),
                success=False,
                error=str(e)
            )
    
    async def _full_recon(self, task: Dict[str, Any]) -> TaskResult:
        """Comprehensive reconnaissance"""
        target = task.get("target", "")
        target_type = task.get("target_type", "url")
        
        start_time = datetime.now()
        results = {
            "target": target,
            "target_type": target_type,
            "started_at": start_time.isoformat(),
            "domain_info": {},
            "ip_info": {},
            "subdomains": [],
            "open_ports": {},
            "technologies": [],
            "osint": {},
            "employees": [],
            "risk_indicators": []
        }
        
        self.set_progress(0.1, "Parsing target")
        
        # Parse target
        domain, ip = self._parse_target(target, target_type)
        
        # 1. Domain/IP resolution
        self.set_progress(0.15, "Resolving DNS")
        results["domain_info"] = await self._get_domain_info(domain) if domain else {}
        results["ip_info"] = await self._get_ip_info(ip) if ip else {}
        
        # 2. Subdomain enumeration
        if domain:
            self.set_progress(0.25, "Enumerating subdomains")
            results["subdomains"] = await self._find_subdomains(domain)
            
            # Broadcast discovered subdomains
            if results["subdomains"]:
                self.broadcast_intel("subdomains", {
                    "domain": domain,
                    "subdomains": results["subdomains"]
                })
        
        # 3. Port scanning
        self.set_progress(0.4, "Scanning ports")
        scan_targets = [ip] if ip else []
        scan_targets.extend(results["subdomains"][:10])  # Top 10 subdomains
        
        for scan_target in scan_targets[:5]:  # Limit to 5 targets
            ports = await self._scan_common_ports(scan_target)
            if ports:
                results["open_ports"][scan_target] = ports
        
        # 4. Technology fingerprinting
        self.set_progress(0.55, "Fingerprinting technology")
        if target_type == "url":
            results["technologies"] = await self._detect_technologies(target)
        
        # 5. OSINT gathering
        self.set_progress(0.7, "Gathering OSINT")
        results["osint"] = await self._comprehensive_osint(domain, ip)
        
        # 6. Risk assessment
        self.set_progress(0.85, "Assessing risks")
        results["risk_indicators"] = self._assess_recon_risks(results)
        
        # Store findings
        for risk in results["risk_indicators"]:
            self.add_finding({
                "type": "reconnaissance",
                "subtype": risk["type"],
                "severity": risk["severity"],
                "description": risk["description"],
                "evidence": risk.get("evidence", ""),
                "location": target
            })
        
        # Update knowledge base
        self.update_knowledge(f"recon_{domain or ip}", results)
        
        results["completed_at"] = datetime.now().isoformat()
        results["duration_seconds"] = (datetime.now() - start_time).total_seconds()
        
        self.set_progress(1.0, "Recon complete")
        
        return TaskResult(
            task_id=task.get("id", ""),
            success=True,
            data=results,
            duration_ms=int(results["duration_seconds"] * 1000)
        )
    
    def _parse_target(self, target: str, target_type: str) -> tuple:
        """Parse target into domain and IP"""
        domain = None
        ip = None
        
        if target_type == "ip":
            ip = target
        elif target_type == "url":
            parsed = urlparse(target)
            domain = parsed.netloc or parsed.path
            domain = domain.split(':')[0]  # Remove port
            
            # Try to resolve IP
            try:
                ip = socket.gethostbyname(domain)
            except:
                pass
        elif target_type == "domain":
            domain = target
            try:
                ip = socket.gethostbyname(domain)
            except:
                pass
        
        return domain, ip
    
    async def _get_domain_info(self, domain: str) -> Dict:
        """Get domain information"""
        info = {
            "domain": domain,
            "resolved_ips": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": []
        }
        
        try:
            # A records
            info["resolved_ips"] = socket.gethostbyname_ex(domain)[2]
        except:
            pass
        
        # DNS queries would go here with dnspython
        # For now, basic info
        
        return info
    
    async def _get_ip_info(self, ip: str) -> Dict:
        """Get IP information"""
        info = {
            "ip": ip,
            "reverse_dns": "",
            "geolocation": {},
            "asn": "",
            "organization": ""
        }
        
        try:
            info["reverse_dns"] = socket.gethostbyaddr(ip)[0]
        except:
            pass
        
        # Would integrate with IP geolocation APIs
        
        return info
    
    async def _find_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains"""
        subdomains = set()
        
        # Common subdomain prefixes
        common_prefixes = [
            "www", "mail", "ftp", "admin", "api", "dev", "staging",
            "test", "beta", "app", "portal", "vpn", "remote", "secure",
            "m", "mobile", "blog", "shop", "store", "cdn", "assets",
            "static", "img", "images", "media", "video", "docs",
            "support", "help", "status", "jenkins", "gitlab", "git",
            "jira", "confluence", "wiki", "internal", "intranet"
        ]
        
        # Basic DNS brute force
        for prefix in common_prefixes:
            subdomain = f"{prefix}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                subdomains.add(subdomain)
                self.discovered_subdomains.append(subdomain)
            except:
                pass
        
        # Would integrate with:
        # - Certificate Transparency logs
        # - SecurityTrails API
        # - Censys
        # - VirusTotal
        # - Subfinder/Amass
        
        return list(subdomains)
    
    async def _scan_common_ports(self, target: str) -> List[Dict]:
        """Quick scan of common ports"""
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
            445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443
        ]
        
        open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    service = self._identify_service(port)
                    open_ports.append({
                        "port": port,
                        "service": service,
                        "state": "open"
                    })
                    
                    # Add finding for interesting ports
                    if port in [21, 22, 23, 3389, 5900]:
                        self.add_finding({
                            "type": "open_port",
                            "severity": "medium" if port in [22, 3389] else "high",
                            "description": f"Remote access service exposed: {service} on port {port}",
                            "location": f"{target}:{port}",
                            "evidence": f"Port {port} is open and accepting connections"
                        })
            except:
                pass
        
        if target not in self.discovered_ports:
            self.discovered_ports[target] = []
        self.discovered_ports[target].extend([p["port"] for p in open_ports])
        
        return open_ports
    
    def _identify_service(self, port: int) -> str:
        """Identify common services by port"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
            135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
            445: "SMB", 993: "IMAPS", 995: "POP3S", 1723: "PPTP",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
        }
        return services.get(port, "unknown")
    
    async def _detect_technologies(self, url: str) -> List[Dict]:
        """Detect technology stack"""
        technologies = []
        
        try:
            import subprocess
            
            # Use curl to get headers
            result = subprocess.run(
                ["curl", "-sI", "-m", "10", url],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            headers = result.stdout.lower()
            
            # Server detection
            if "apache" in headers:
                technologies.append({"name": "Apache", "category": "web_server"})
            if "nginx" in headers:
                technologies.append({"name": "Nginx", "category": "web_server"})
            if "iis" in headers:
                technologies.append({"name": "IIS", "category": "web_server"})
            
            # Framework detection
            if "x-powered-by: php" in headers:
                technologies.append({"name": "PHP", "category": "language"})
            if "x-powered-by: asp" in headers:
                technologies.append({"name": "ASP.NET", "category": "framework"})
            if "x-powered-by: express" in headers:
                technologies.append({"name": "Express.js", "category": "framework"})
            
            # Security headers check
            security_missing = []
            if "x-frame-options" not in headers:
                security_missing.append("X-Frame-Options")
            if "x-content-type-options" not in headers:
                security_missing.append("X-Content-Type-Options")
            if "strict-transport-security" not in headers:
                security_missing.append("Strict-Transport-Security")
            if "content-security-policy" not in headers:
                security_missing.append("Content-Security-Policy")
            
            if security_missing:
                self.add_finding({
                    "type": "missing_security_headers",
                    "severity": "medium",
                    "description": f"Missing security headers: {', '.join(security_missing)}",
                    "location": url,
                    "evidence": f"Headers not present in response"
                })
                technologies.append({
                    "name": "Missing Security Headers",
                    "category": "security_issue",
                    "details": security_missing
                })
            
        except Exception as e:
            logger.warning(f"Technology detection failed: {e}")
        
        self.tech_stack[url] = technologies
        return technologies
    
    async def _comprehensive_osint(self, domain: Optional[str], ip: Optional[str]) -> Dict:
        """Gather OSINT from multiple sources"""
        osint = {
            "shodan": {},
            "virustotal": {},
            "breach_data": {},
            "social_media": {},
            "code_repos": {}
        }
        
        # Shodan lookup
        if self.api_keys.get("shodan") and ip:
            osint["shodan"] = await self._query_shodan(ip)
        
        # VirusTotal
        if self.api_keys.get("virustotal") and domain:
            osint["virustotal"] = await self._query_virustotal(domain)
        
        # Check for common data leaks (simulated)
        if domain:
            osint["breach_data"] = await self._check_breaches(domain)
        
        # GitHub/GitLab code search (for leaked secrets)
        if domain:
            osint["code_repos"] = await self._search_code_repos(domain)
        
        return osint
    
    async def _query_shodan(self, ip: str) -> Dict:
        """Query Shodan for IP information"""
        # Would use shodan library
        # For now, return placeholder
        return {
            "status": "api_key_required",
            "ip": ip,
            "note": "Configure SHODAN_API_KEY for live data"
        }
    
    async def _query_virustotal(self, domain: str) -> Dict:
        """Query VirusTotal for domain reputation"""
        return {
            "status": "api_key_required",
            "domain": domain,
            "note": "Configure VIRUSTOTAL_API_KEY for live data"
        }
    
    async def _check_breaches(self, domain: str) -> Dict:
        """Check for known data breaches"""
        # Would integrate with HaveIBeenPwned API
        return {
            "status": "check_manually",
            "domain": domain,
            "recommended_check": f"https://haveibeenpwned.com/DomainSearch/{domain}"
        }
    
    async def _search_code_repos(self, domain: str) -> Dict:
        """Search for leaked code/secrets in public repos"""
        # Would use GitHub/GitLab APIs
        search_patterns = [
            f'"{domain}" password',
            f'"{domain}" api_key',
            f'"{domain}" secret',
            f'"{domain}" AWS_SECRET'
        ]
        
        return {
            "status": "manual_search_recommended",
            "search_patterns": search_patterns,
            "github_url": f"https://github.com/search?q={domain}+password&type=code"
        }
    
    async def _enumerate_subdomains(self, task: Dict[str, Any]) -> TaskResult:
        """Standalone subdomain enumeration task"""
        domain = task.get("target", "")
        subdomains = await self._find_subdomains(domain)
        
        return TaskResult(
            task_id=task.get("id", ""),
            success=True,
            data={"domain": domain, "subdomains": subdomains}
        )
    
    async def _gather_osint(self, task: Dict[str, Any]) -> TaskResult:
        """Standalone OSINT gathering task"""
        target = task.get("target", "")
        target_type = task.get("target_type", "domain")
        
        domain, ip = self._parse_target(target, target_type)
        osint = await self._comprehensive_osint(domain, ip)
        
        return TaskResult(
            task_id=task.get("id", ""),
            success=True,
            data=osint
        )
    
    async def _coordinate_port_scan(self, task: Dict[str, Any]) -> TaskResult:
        """Coordinate port scanning"""
        target = task.get("target", "")
        ports = await self._scan_common_ports(target)
        
        return TaskResult(
            task_id=task.get("id", ""),
            success=True,
            data={"target": target, "open_ports": ports}
        )
    
    async def _fingerprint_tech(self, task: Dict[str, Any]) -> TaskResult:
        """Fingerprint technology stack"""
        url = task.get("target", "")
        tech = await self._detect_technologies(url)
        
        return TaskResult(
            task_id=task.get("id", ""),
            success=True,
            data={"url": url, "technologies": tech}
        )
    
    def _assess_recon_risks(self, results: Dict) -> List[Dict]:
        """Assess risks from reconnaissance results"""
        risks = []
        
        # Check for exposed sensitive ports
        for target, ports in results.get("open_ports", {}).items():
            for port_info in ports:
                port = port_info["port"]
                if port in [21, 23, 3389, 5900]:
                    risks.append({
                        "type": "exposed_remote_access",
                        "severity": "high",
                        "description": f"Remote access service {port_info['service']} exposed on {target}:{port}",
                        "evidence": f"Port {port} is open"
                    })
                elif port == 3306:
                    risks.append({
                        "type": "exposed_database",
                        "severity": "critical",
                        "description": f"MySQL database exposed on {target}:{port}",
                        "evidence": "Port 3306 is accepting connections"
                    })
                elif port == 5432:
                    risks.append({
                        "type": "exposed_database",
                        "severity": "critical",
                        "description": f"PostgreSQL database exposed on {target}:{port}",
                        "evidence": "Port 5432 is accepting connections"
                    })
        
        # Check for many subdomains (larger attack surface)
        subdomain_count = len(results.get("subdomains", []))
        if subdomain_count > 20:
            risks.append({
                "type": "large_attack_surface",
                "severity": "medium",
                "description": f"Large number of subdomains discovered ({subdomain_count})",
                "evidence": f"Found {subdomain_count} subdomains"
            })
        
        # Check tech stack for known vulnerable components
        for tech in results.get("technologies", []):
            if tech.get("category") == "security_issue":
                risks.append({
                    "type": "security_misconfiguration",
                    "severity": "medium",
                    "description": tech.get("name", "Security issue detected"),
                    "evidence": str(tech.get("details", ""))
                })
        
        return risks
