"""
Base Tool class and Factory for creating tool instances
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import subprocess
import logging

logger = logging.getLogger(__name__)

class BaseTool(ABC):
    """Abstract base class for all tools"""
    
    def __init__(self, name: str, timeout: int = 300):
        self.name = name
        self.timeout = timeout
    
    @abstractmethod
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with given parameters.
        
        Returns:
            {
                "stdout": str,
                "stderr": str,
                "return_code": int,
                "status": ExecutionStatus,
                "error_message": Optional[str]
            }
        """
        pass
    
    def _run_command(self, command: list, input_data: Optional[str] = None) -> Dict[str, Any]:
        """
        Safely run a subprocess command with timeout.
        """
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                input=input_data
            )
            
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode,
                "status": "success" if result.returncode == 0 else "failed"
            }
        except subprocess.TimeoutExpired as e:
            logger.error(f"Timeout executing {self.name}: {e}")
            return {
                "stdout": "",
                "stderr": f"Command timeout after {self.timeout}s",
                "return_code": 124,
                "status": "failed",
                "error_message": str(e)
            }
        except Exception as e:
            logger.error(f"Error executing {self.name}: {e}")
            return {
                "stdout": "",
                "stderr": str(e),
                "return_code": 1,
                "status": "error",
                "error_message": str(e)
            }


class NmapTool(BaseTool):
    """Network scanning with Nmap"""
    
    def __init__(self):
        super().__init__("nmap", timeout=300)
    
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute Nmap scan.
        
        Params:
            target: IP or hostname
            ports: Optional port specification (e.g., "1-1000", "22,80,443")
            scan_type: Optional ("syn", "udp", "aggressive")
            output_format: Optional ("normal", "xml", "json")
        """
        
        target = params.get("target", "localhost")
        ports = params.get("ports", "1-10000")
        scan_type = params.get("scan_type", "syn")
        
        command = ["nmap"]
        
        # Add scan type
        if scan_type == "syn":
            command.append("-sS")
        elif scan_type == "udp":
            command.append("-sU")
        elif scan_type == "aggressive":
            command.extend(["-A", "-T4"])
        
        # Add ports
        if ports:
            command.extend(["-p", ports])
        
        # Add service detection
        command.append("-sV")
        
        # Add output format
        command.extend(["-oN", "-"])  # Output to stdout
        
        # Add target
        command.append(target)
        
        logger.info(f"Running Nmap: {' '.join(command)}")
        return self._run_command(command)


class SqlmapTool(BaseTool):
    """SQL injection testing with SQLmap"""
    
    def __init__(self):
        super().__init__("sqlmap", timeout=600)
    
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute SQLmap scan.
        
        Params:
            url: Target URL
            method: HTTP method (GET, POST)
            data: Optional POST data
            dbs: If true, enumerate databases
            tables: If true, enumerate tables
            risk: Risk level (1, 2, 3)
        """
        
        url = params.get("url")
        method = params.get("method", "GET")
        data = params.get("data")
        dbs = params.get("dbs", False)
        tables = params.get("tables", False)
        risk = params.get("risk", "1")
        
        if not url:
            return {
                "stdout": "",
                "stderr": "URL parameter is required",
                "return_code": 1,
                "status": "error",
                "error_message": "Missing URL"
            }
        
        command = ["sqlmap", "-u", url]
        
        if method:
            command.extend(["--method", method])
        
        if data:
            command.extend(["-d", data])
        
        if dbs:
            command.append("--dbs")
        
        if tables:
            command.append("--tables")
        
        command.extend(["--risk", risk])
        command.append("-v 1")  # Minimal verbose
        
        logger.info(f"Running SQLmap: {' '.join(command)}")
        return self._run_command(command)


class CurlTool(BaseTool):
    """HTTP requests with Curl"""
    
    def __init__(self):
        super().__init__("curl", timeout=30)
    
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute HTTP request.
        
        Params:
            url: Target URL
            method: HTTP method (GET, POST, etc.)
            headers: Dict of headers
            data: Request body
            follow_redirects: Boolean
            username/password: For basic auth
        """
        
        url = params.get("url")
        method = params.get("method", "GET")
        headers = params.get("headers", {})
        data = params.get("data")
        follow_redirects = params.get("follow_redirects", False)
        username = params.get("username")
        password = params.get("password")
        
        if not url:
            return {
                "stdout": "",
                "stderr": "URL parameter is required",
                "return_code": 1,
                "status": "error"
            }
        
        command = ["curl"]
        
        if method and method != "GET":
            command.extend(["-X", method])
        
        for key, value in headers.items():
            command.extend(["-H", f"{key}: {value}"])
        
        if data:
            command.extend(["-d", data])
        
        if follow_redirects:
            command.append("-L")
        
        if username and password:
            command.extend(["-u", f"{username}:{password}"])
        
        command.append("-v")  # Verbose for headers
        command.append(url)
        
        logger.info(f"Running Curl: {' '.join(command[:5])}...")
        return self._run_command(command)


class HydraTool(BaseTool):
    """Credential brute-forcing with Hydra"""
    
    def __init__(self):
        super().__init__("hydra", timeout=600)
    
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute Hydra brute-force attack.
        
        Params:
            target: Target host
            service: Service type (http-post, ftp, ssh, mysql, etc.)
            username_list: File or single username
            password_list: File or single password
            port: Target port
        """
        
        target = params.get("target")
        service = params.get("service", "http-post")
        username = params.get("username")
        password_list = params.get("password_list", "/usr/share/wordlists/rockyou.txt")
        port = params.get("port", "80")
        
        if not target:
            return {
                "stdout": "",
                "stderr": "Target parameter is required",
                "return_code": 1,
                "status": "error"
            }
        
        command = ["hydra"]
        command.extend(["-l", username])
        command.extend(["-P", password_list])
        command.extend(["-p", port])
        command.extend(["-o", "-"])  # Output to stdout
        command.append(target)
        command.append(service)
        
        logger.info(f"Running Hydra: {' '.join(command[:7])}...")
        return self._run_command(command)


class ToolFactory:
    """Factory for creating and managing tool instances"""
    
    def __init__(self):
        self.tools = {
            "nmap": NmapTool(),
            "sqlmap": SqlmapTool(),
            "curl": CurlTool(),
            "hydra": HydraTool(),
        }
    
    def get_tool(self, tool_name: str) -> Optional[BaseTool]:
        """Get a tool instance by name"""
        return self.tools.get(tool_name.lower())
    
    def list_tools(self):
        """List available tools"""
        return list(self.tools.keys())
