"""
OSINT Intelligence Hub - Open Source Intelligence Integration
==============================================================

Centralized intelligence gathering from multiple sources:
- Shodan: Internet-connected device search
- Censys: Certificate and host discovery
- VirusTotal: Malware and URL reputation
- SecurityTrails: DNS and historical data
- HaveIBeenPwned: Breach data
- Hunter.io: Email discovery
- GitHub: Secret leak detection
"""

import asyncio
import logging
import json
import re
import os
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, quote
import hashlib

logger = logging.getLogger(__name__)


class OSINTHub:
    """
    Central hub for OSINT data gathering and correlation.
    Integrates multiple intelligence sources.
    """
    
    def __init__(self, api_keys: Optional[Dict[str, str]] = None):
        self.api_keys = api_keys or {}
        
        # Intelligence cache
        self.intel_cache: Dict[str, Dict] = {}
        self.cache_ttl = 3600  # 1 hour
        
        # Enabled sources
        self.sources = {
            "shodan": ShodanSource(self.api_keys.get("shodan", "")),
            "censys": CensysSource(
                self.api_keys.get("censys_id", ""),
                self.api_keys.get("censys_secret", "")
            ),
            "virustotal": VirusTotalSource(self.api_keys.get("virustotal", "")),
            "securitytrails": SecurityTrailsSource(self.api_keys.get("securitytrails", "")),
            "hunter": HunterSource(self.api_keys.get("hunter", "")),
        }
        
        logger.info(f"OSINT Hub initialized with sources: {[k for k, v in self.sources.items() if v.is_configured()]}")
    
    async def gather_intelligence(
        self,
        target: str,
        target_type: str = "domain",
        sources: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Gather intelligence from all configured sources
        """
        cache_key = f"{target_type}:{target}"
        
        # Check cache
        if cache_key in self.intel_cache:
            cached = self.intel_cache[cache_key]
            if (datetime.now() - cached["timestamp"]).seconds < self.cache_ttl:
                logger.info(f"Returning cached intel for {target}")
                return cached["data"]
        
        intel = {
            "target": target,
            "target_type": target_type,
            "gathered_at": datetime.now().isoformat(),
            "sources": {},
            "summary": {},
            "risk_indicators": [],
            "correlations": []
        }
        
        # Determine which sources to query
        active_sources = sources or list(self.sources.keys())
        
        # Gather from each source
        tasks = []
        for source_name in active_sources:
            source = self.sources.get(source_name)
            if source and source.is_configured():
                tasks.append(self._query_source(source_name, source, target, target_type))
        
        # Execute in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for source_name, result in zip(active_sources, results):
            if isinstance(result, Exception):
                intel["sources"][source_name] = {"error": str(result)}
            else:
                intel["sources"][source_name] = result
        
        # Correlate and summarize
        intel["correlations"] = self._correlate_intel(intel["sources"])
        intel["summary"] = self._summarize_intel(intel["sources"])
        intel["risk_indicators"] = self._extract_risk_indicators(intel)
        
        # Cache result
        self.intel_cache[cache_key] = {
            "timestamp": datetime.now(),
            "data": intel
        }
        
        return intel
    
    async def _query_source(
        self,
        source_name: str,
        source: 'IntelSource',
        target: str,
        target_type: str
    ) -> Dict:
        """Query a single intelligence source"""
        try:
            return await source.query(target, target_type)
        except Exception as e:
            logger.error(f"Error querying {source_name}: {e}")
            return {"error": str(e)}
    
    def _correlate_intel(self, sources: Dict) -> List[Dict]:
        """Correlate intelligence from multiple sources"""
        correlations = []
        
        # Find common IPs across sources
        all_ips = set()
        for source_data in sources.values():
            if isinstance(source_data, dict):
                ips = source_data.get("ip_addresses", [])
                all_ips.update(ips)
        
        if len(all_ips) > 1:
            correlations.append({
                "type": "multiple_ips",
                "description": f"Target resolves to {len(all_ips)} IP addresses",
                "data": list(all_ips)
            })
        
        # Find open ports correlation
        all_ports = set()
        for source_data in sources.values():
            if isinstance(source_data, dict):
                ports = source_data.get("open_ports", [])
                all_ports.update([p.get("port") if isinstance(p, dict) else p for p in ports])
        
        if all_ports:
            correlations.append({
                "type": "port_exposure",
                "description": f"Found {len(all_ports)} unique open ports",
                "data": sorted(list(all_ports))
            })
        
        return correlations
    
    def _summarize_intel(self, sources: Dict) -> Dict:
        """Summarize intelligence findings"""
        summary = {
            "total_sources_queried": len(sources),
            "successful_queries": sum(1 for s in sources.values() if "error" not in s),
            "total_ips_found": 0,
            "total_ports_found": 0,
            "total_subdomains": 0,
            "breach_data_found": False,
            "malicious_indicators": 0
        }
        
        for source_data in sources.values():
            if isinstance(source_data, dict) and "error" not in source_data:
                summary["total_ips_found"] += len(source_data.get("ip_addresses", []))
                summary["total_ports_found"] += len(source_data.get("open_ports", []))
                summary["total_subdomains"] += len(source_data.get("subdomains", []))
                
                if source_data.get("breaches"):
                    summary["breach_data_found"] = True
                
                summary["malicious_indicators"] += source_data.get("malicious_count", 0)
        
        return summary
    
    def _extract_risk_indicators(self, intel: Dict) -> List[Dict]:
        """Extract risk indicators from intelligence"""
        risks = []
        
        summary = intel.get("summary", {})
        
        # High port exposure
        if summary.get("total_ports_found", 0) > 10:
            risks.append({
                "type": "high_exposure",
                "severity": "medium",
                "description": f"High number of exposed ports ({summary['total_ports_found']})"
            })
        
        # Breach data found
        if summary.get("breach_data_found"):
            risks.append({
                "type": "data_breach",
                "severity": "high",
                "description": "Organization appears in known data breaches"
            })
        
        # Malicious indicators
        if summary.get("malicious_indicators", 0) > 0:
            risks.append({
                "type": "malicious_activity",
                "severity": "high",
                "description": f"Target has {summary['malicious_indicators']} malicious indicators"
            })
        
        # Large attack surface
        if summary.get("total_subdomains", 0) > 50:
            risks.append({
                "type": "large_attack_surface",
                "severity": "medium",
                "description": f"Large subdomain footprint ({summary['total_subdomains']} subdomains)"
            })
        
        return risks
    
    async def search_leaked_credentials(self, domain: str) -> Dict:
        """Search for leaked credentials related to domain"""
        results = {
            "domain": domain,
            "breaches": [],
            "paste_mentions": [],
            "credential_dumps": []
        }
        
        # Would integrate with breach databases
        # For now, return structure
        
        return results
    
    async def search_code_leaks(self, domain: str) -> Dict:
        """Search for secrets leaked in code repositories"""
        search_patterns = [
            f'"{domain}" password',
            f'"{domain}" api_key',
            f'"{domain}" secret',
            f'"{domain}" token',
            f'"{domain}" AWS',
        ]
        
        results = {
            "domain": domain,
            "patterns_searched": search_patterns,
            "potential_leaks": [],
            "repositories": []
        }
        
        # Would integrate with GitHub/GitLab APIs
        
        return results


class IntelSource:
    """Base class for intelligence sources"""
    
    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self.base_url = ""
        self.rate_limit = 1.0  # seconds between requests
        self.last_request = None
    
    def is_configured(self) -> bool:
        """Check if source is configured"""
        return bool(self.api_key)
    
    async def query(self, target: str, target_type: str) -> Dict:
        """Query the intelligence source"""
        raise NotImplementedError
    
    async def _rate_limit(self):
        """Apply rate limiting"""
        if self.last_request:
            elapsed = (datetime.now() - self.last_request).total_seconds()
            if elapsed < self.rate_limit:
                await asyncio.sleep(self.rate_limit - elapsed)
        self.last_request = datetime.now()


class ShodanSource(IntelSource):
    """Shodan intelligence source"""
    
    def __init__(self, api_key: str = ""):
        super().__init__(api_key)
        self.base_url = "https://api.shodan.io"
    
    async def query(self, target: str, target_type: str) -> Dict:
        if not self.is_configured():
            return {"status": "not_configured", "note": "Set SHODAN_API_KEY"}
        
        await self._rate_limit()
        
        result = {
            "source": "shodan",
            "target": target,
            "ip_addresses": [],
            "open_ports": [],
            "services": [],
            "vulnerabilities": [],
            "hostnames": [],
            "os": None,
            "organization": None
        }
        
        try:
            import subprocess
            
            # Use curl to query Shodan API
            if target_type == "ip":
                url = f"{self.base_url}/shodan/host/{target}?key={self.api_key}"
            else:
                url = f"{self.base_url}/dns/resolve?hostnames={target}&key={self.api_key}"
            
            proc = subprocess.run(
                ["curl", "-s", "-m", "30", url],
                capture_output=True,
                text=True,
                timeout=35
            )
            
            if proc.stdout:
                data = json.loads(proc.stdout)
                
                if target_type == "ip":
                    result["open_ports"] = data.get("ports", [])
                    result["hostnames"] = data.get("hostnames", [])
                    result["os"] = data.get("os")
                    result["organization"] = data.get("org")
                    result["vulnerabilities"] = data.get("vulns", [])
                    
                    for service in data.get("data", []):
                        result["services"].append({
                            "port": service.get("port"),
                            "protocol": service.get("transport"),
                            "product": service.get("product"),
                            "version": service.get("version")
                        })
                else:
                    result["ip_addresses"] = list(data.values()) if isinstance(data, dict) else []
                    
        except Exception as e:
            result["error"] = str(e)
        
        return result


class CensysSource(IntelSource):
    """Censys intelligence source"""
    
    def __init__(self, api_id: str = "", api_secret: str = ""):
        super().__init__(api_id)
        self.api_secret = api_secret
        self.base_url = "https://search.censys.io/api/v2"
    
    def is_configured(self) -> bool:
        return bool(self.api_key and self.api_secret)
    
    async def query(self, target: str, target_type: str) -> Dict:
        if not self.is_configured():
            return {"status": "not_configured", "note": "Set CENSYS_API_ID and CENSYS_API_SECRET"}
        
        result = {
            "source": "censys",
            "target": target,
            "certificates": [],
            "services": [],
            "protocols": []
        }
        
        # Would implement Censys API queries
        
        return result


class VirusTotalSource(IntelSource):
    """VirusTotal intelligence source"""
    
    def __init__(self, api_key: str = ""):
        super().__init__(api_key)
        self.base_url = "https://www.virustotal.com/api/v3"
    
    async def query(self, target: str, target_type: str) -> Dict:
        if not self.is_configured():
            return {"status": "not_configured", "note": "Set VIRUSTOTAL_API_KEY"}
        
        await self._rate_limit()
        
        result = {
            "source": "virustotal",
            "target": target,
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "categories": [],
            "last_analysis_date": None
        }
        
        try:
            import subprocess
            
            if target_type in ["domain", "url"]:
                endpoint = "domains" if target_type == "domain" else "urls"
                
                if target_type == "url":
                    # URL needs to be base64 encoded
                    import base64
                    target = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
                
                url = f"{self.base_url}/{endpoint}/{target}"
                
                proc = subprocess.run(
                    ["curl", "-s", "-m", "30", "-H", f"x-apikey: {self.api_key}", url],
                    capture_output=True,
                    text=True,
                    timeout=35
                )
                
                if proc.stdout:
                    data = json.loads(proc.stdout)
                    attrs = data.get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    
                    result["malicious_count"] = stats.get("malicious", 0)
                    result["suspicious_count"] = stats.get("suspicious", 0)
                    result["harmless_count"] = stats.get("harmless", 0)
                    result["categories"] = list(attrs.get("categories", {}).values())
                    result["last_analysis_date"] = attrs.get("last_analysis_date")
                    
        except Exception as e:
            result["error"] = str(e)
        
        return result


class SecurityTrailsSource(IntelSource):
    """SecurityTrails intelligence source"""
    
    def __init__(self, api_key: str = ""):
        super().__init__(api_key)
        self.base_url = "https://api.securitytrails.com/v1"
    
    async def query(self, target: str, target_type: str) -> Dict:
        if not self.is_configured():
            return {"status": "not_configured", "note": "Set SECURITYTRAILS_API_KEY"}
        
        result = {
            "source": "securitytrails",
            "target": target,
            "subdomains": [],
            "dns_history": [],
            "whois": {}
        }
        
        try:
            import subprocess
            
            if target_type == "domain":
                # Get subdomains
                url = f"{self.base_url}/domain/{target}/subdomains"
                
                proc = subprocess.run(
                    ["curl", "-s", "-m", "30", "-H", f"APIKEY: {self.api_key}", url],
                    capture_output=True,
                    text=True,
                    timeout=35
                )
                
                if proc.stdout:
                    data = json.loads(proc.stdout)
                    result["subdomains"] = [
                        f"{sub}.{target}" for sub in data.get("subdomains", [])
                    ]
                    
        except Exception as e:
            result["error"] = str(e)
        
        return result


class HunterSource(IntelSource):
    """Hunter.io email discovery source"""
    
    def __init__(self, api_key: str = ""):
        super().__init__(api_key)
        self.base_url = "https://api.hunter.io/v2"
    
    async def query(self, target: str, target_type: str) -> Dict:
        if not self.is_configured():
            return {"status": "not_configured", "note": "Set HUNTER_API_KEY"}
        
        result = {
            "source": "hunter",
            "target": target,
            "emails": [],
            "email_pattern": None,
            "organization": None
        }
        
        try:
            import subprocess
            
            if target_type == "domain":
                url = f"{self.base_url}/domain-search?domain={target}&api_key={self.api_key}"
                
                proc = subprocess.run(
                    ["curl", "-s", "-m", "30", url],
                    capture_output=True,
                    text=True,
                    timeout=35
                )
                
                if proc.stdout:
                    data = json.loads(proc.stdout)
                    emails_data = data.get("data", {}).get("emails", [])
                    
                    result["emails"] = [
                        {
                            "email": e.get("value"),
                            "type": e.get("type"),
                            "first_name": e.get("first_name"),
                            "last_name": e.get("last_name"),
                            "position": e.get("position")
                        }
                        for e in emails_data[:50]  # Limit to 50
                    ]
                    result["email_pattern"] = data.get("data", {}).get("pattern")
                    result["organization"] = data.get("data", {}).get("organization")
                    
        except Exception as e:
            result["error"] = str(e)
        
        return result


# Singleton instance
_osint_hub: Optional[OSINTHub] = None

def get_osint_hub(api_keys: Optional[Dict] = None) -> OSINTHub:
    """Get or create OSINT hub singleton"""
    global _osint_hub

    resolved_keys = api_keys or {
        "shodan": os.getenv("SHODAN_API_KEY", "").strip(),
        "virustotal": os.getenv("VIRUSTOTAL_API_KEY", "").strip(),
        "censys_id": os.getenv("CENSYS_API_ID", "").strip(),
        "censys_secret": os.getenv("CENSYS_API_SECRET", "").strip(),
        "securitytrails": os.getenv("SECURITYTRAILS_API_KEY", "").strip(),
        "hunter": os.getenv("HUNTER_API_KEY", "").strip(),
    }

    if _osint_hub is None:
        _osint_hub = OSINTHub(resolved_keys)
    else:
        existing_configured = any(source.is_configured() for source in _osint_hub.sources.values())
        incoming_configured = any(bool(v) for v in resolved_keys.values())

        # Rebuild singleton when explicit keys are provided, or when stale empty state is detected.
        if api_keys is not None or (incoming_configured and not existing_configured):
            _osint_hub = OSINTHub(resolved_keys)

    return _osint_hub
