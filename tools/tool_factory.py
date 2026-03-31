"""
Base Tool class and Factory for creating tool instances
Enhanced with retry logic, timeout handling, and graceful degradation
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
import subprocess
import logging
import time
import shutil

logger = logging.getLogger(__name__)

class ToolUnavailableError(Exception):
    """Raised when a required tool is not available"""
    pass

class BaseTool(ABC):
    """Abstract base class for all tools with retry and timeout support"""
    
    def __init__(self, name: str, timeout: int = 300, max_retries: int = 2):
        self.name = name
        self.timeout = timeout
        self.max_retries = max_retries
        self.execution_count = 0
        self.failure_count = 0
        self._check_availability()
    
    def _check_availability(self):
        """Check if the tool is available in the system"""
        # Default implementation - can be overridden
        pass
    
    @abstractmethod
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with given parameters.
        
        Returns:
            {
                "stdout": str,
                "stderr": str,
                "return_code": int,
                "status": "success"|"failed"|"error"|"timeout",
                "error_message": Optional[str],
                "execution_time": float,
                "retries_used": int
            }
        """
        pass
    
    def _run_command(
        self, 
        command: List[str], 
        input_data: Optional[str] = None,
        retry_on_timeout: bool = True
    ) -> Dict[str, Any]:
        """
        Safely run a subprocess command with timeout and retry logic.
        """
        self.execution_count += 1
        retries_used = 0
        last_error = None
        
        for attempt in range(self.max_retries + 1):
            start_time = time.time()
            try:
                logger.debug(f"[{self.name}] Execution attempt {attempt + 1}/{self.max_retries + 1}")
                
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    input=input_data
                )
                
                execution_time = time.time() - start_time
                
                return {
                    "stdout": result.stdout[:5000],  # Limit output size
                    "stderr": result.stderr[:1000],
                    "return_code": result.returncode,
                    "status": "success" if result.returncode == 0 else "failed",
                    "error_message": None,
                    "execution_time": execution_time,
                    "retries_used": retries_used
                }
                
            except subprocess.TimeoutExpired as e:
                last_error = e
                execution_time = time.time() - start_time
                logger.warning(f"[{self.name}] Timeout after {execution_time:.1f}s on attempt {attempt + 1}")
                
                if attempt < self.max_retries and retry_on_timeout:
                    retries_used += 1
                    wait_time = min(2 ** attempt, 10)  # Exponential backoff, max 10s
                    logger.info(f"[{self.name}] Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                    continue
                else:
                    self.failure_count += 1
                    return {
                        "stdout": "",
                        "stderr": f"Command timeout after {self.timeout}s",
                        "return_code": 124,
                        "status": "timeout",
                        "error_message": f"Timeout: {str(e)}",
                        "execution_time": execution_time,
                        "retries_used": retries_used
                    }
                    
            except Exception as e:
                last_error = e
                execution_time = time.time() - start_time
                logger.error(f"[{self.name}] Execution error on attempt {attempt + 1}: {e}")
                
                if attempt < self.max_retries:
                    retries_used += 1
                    wait_time = min(2 ** attempt, 10)
                    logger.info(f"[{self.name}] Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                    continue
                else:
                    self.failure_count += 1
                    return {
                        "stdout": "",
                        "stderr": str(e),
                        "return_code": 1,
                        "status": "error",
                        "error_message": str(e),
                        "execution_time": execution_time,
                        "retries_used": retries_used
                    }
        
        # Should not reach here, but just in case
        return {
            "stdout": "",
            "stderr": str(last_error),
            "return_code": 1,
            "status": "error",
            "error_message": f"Failed after {self.max_retries + 1} attempts: {str(last_error)}",
            "execution_time": 0,
            "retries_used": retries_used
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get tool execution statistics"""
        success_rate = 0
        if self.execution_count > 0:
            success_rate = ((self.execution_count - self.failure_count) / self.execution_count) * 100
        
        return {
            "tool_name": self.name,
            "total_executions": self.execution_count,
            "failures": self.failure_count,
            "success_rate": f"{success_rate:.1f}%"
        }


class NmapTool(BaseTool):
    """Network scanning with Nmap"""
    
    def __init__(self):
        super().__init__("nmap", timeout=120, max_retries=1)
    
    def _check_availability(self):
        """Check if Nmap is installed"""
        if not shutil.which("nmap"):
            logger.warning("Nmap not found in PATH")
    
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute Nmap scan.
        
        Params:
            target: IP or hostname
            ports: Optional port specification (e.g., "1-1000", "22,80,443")
            scan_type: Optional ("syn", "udp", "aggressive")
        """
        
        target = params.get("target", "localhost")
        ports = params.get("ports", "1-1000")  # Reduced from 10000 for faster scanning
        scan_type = params.get("scan_type", "syn")
        
        # Validate target
        if not target or target.strip() == "":
            logger.error("[nmap] Empty target provided")
            return {
                "stdout": "",
                "stderr": "Target is required",
                "return_code": 1,
                "status": "error",
                "error_message": "Missing target parameter",
                "execution_time": 0,
                "retries_used": 0
            }
        
        command = ["nmap", "-T3"]  # Add timing option for reliability
        
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
        
        # Add service detection and output
        command.extend(["-sV", "-oN", "-"])
        command.append(target)
        
        logger.info(f"[nmap] Running: {' '.join(command)}")
        return self._run_command(command, retry_on_timeout=True)



class SqlmapTool(BaseTool):
    """SQL injection testing with SQLmap"""
    
    def __init__(self):
        super().__init__("sqlmap", timeout=60, max_retries=1)  # Reduced timeout for faster execution
    
    def _check_availability(self):
        """Check if SQLmap is installed"""
        if not shutil.which("sqlmap"):
            logger.warning("SQLmap not found in PATH")
    
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute SQLmap scan.
        
        Params:
            url: Target URL
            level: Test level (1-5)
            risk: Risk level (1-3)
        """
        
        url = params.get("url")
        level = params.get("level", 1)
        risk = params.get("risk", 1)
        
        # Validate URL
        if not url or not (url.startswith("http://") or url.startswith("https://")):
            logger.error("[sqlmap] Invalid URL provided")
            return {
                "stdout": "",
                "stderr": "Valid URL (http:// or https://) is required",
                "return_code": 1,
                "status": "error",
                "error_message": "Invalid URL parameter",
                "execution_time": 0,
                "retries_used": 0
            }
        
        command = ["sqlmap", "-u", url]
        command.extend(["--level", str(level)])
        command.extend(["--risk", str(risk)])
        command.append("-v 0")  # Minimal output
        command.append("--batch")  # Non-interactive
        
        logger.info(f"[sqlmap] Running: {' '.join(command[:5])}...")
        return self._run_command(command, retry_on_timeout=False)



class CurlTool(BaseTool):
    """HTTP requests with Curl"""
    
    def __init__(self):
        super().__init__("curl", timeout=20, max_retries=2)
    
    def _check_availability(self):
        """Check if Curl is installed"""
        if not shutil.which("curl"):
            logger.warning("Curl not found in PATH")
    
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute HTTP request.
        
        Params:
            url: Target URL
            method: HTTP method (GET, POST, etc.)
            headers: Dict of headers
            data: Request body
            username/password: For basic auth
        """
        
        url = params.get("url")
        method = params.get("method", "GET")
        headers = params.get("headers", {}) or {}
        data = params.get("data")
        username = params.get("username")
        password = params.get("password")
        
        # Validate URL
        if not url or not (url.startswith("http://") or url.startswith("https://")):
            logger.error("[curl] Invalid URL provided")
            return {
                "stdout": "",
                "stderr": "Valid URL is required",
                "return_code": 1,
                "status": "error",
                "error_message": "Invalid URL parameter",
                "execution_time": 0,
                "retries_used": 0
            }
        
        command = ["curl", "-s", "--max-time", str(self.timeout - 2)]
        
        if method and method != "GET":
            command.extend(["-X", method])
        
        # Handle headers safely
        if isinstance(headers, dict):
            for key, value in headers.items():
                if value:
                    safe_value = str(value).replace('"', '\\"')
                    command.extend(["-H", f"{key}: {safe_value}"])
        
        if data:
            safe_data = str(data).replace('"', '\\"')
            command.extend(["-d", safe_data])
        
        if username and password:
            command.extend(["-u", f"{username}:{password}"])
        
        command.append(url)
        
        logger.info(f"[curl] Running request to {url[:50]}...")
        return self._run_command(command, retry_on_timeout=True)



class HydraTool(BaseTool):
    """Credential brute-forcing with Hydra"""
    
    def __init__(self):
        super().__init__("hydra", timeout=180, max_retries=1)
    
    def _check_availability(self):
        """Check if Hydra is installed"""
        if not shutil.which("hydra"):
            logger.warning("Hydra not found in PATH")
    
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute Hydra brute-force attack.
        
        Params:
            target: Target host
            service: Service type (http-post, ftp, etc.)
            username: Username to test
        """
        
        target = params.get("target")
        service = params.get("service", "http-post")
        username = params.get("username", "admin")
        
        # Validate target
        if not target or target.strip() == "":
            logger.error("[hydra] Empty target provided")
            return {
                "stdout": "",
                "stderr": "Target is required",
                "return_code": 1,
                "status": "error",
                "error_message": "Missing target parameter",
                "execution_time": 0,
                "retries_used": 0
            }
        
        # Use a small password list for speed
        passwords = ["password", "123456", "admin", "test"]
        
        command = ["hydra"]
        command.extend(["-l", username])
        command.extend(["-P", "-"])  # Read from stdin
        command.append("-vv")
        command.append(target)
        command.append(service)
        
        password_list = "\n".join(passwords)
        
        logger.info(f"[hydra] Running brute-force on {target}:{service}")
        return self._run_command(command, input_data=password_list, retry_on_timeout=False)



class ToolFactory:
    """Factory for creating and managing tool instances with statistics"""
    
    def __init__(self):
        self.tools = {
            "nmap": NmapTool(),
            "sqlmap": SqlmapTool(),
            "curl": CurlTool(),
            "hydra": HydraTool(),
        }
        logger.info(f"[ToolFactory] Initialized with tools: {list(self.tools.keys())}")
    
    def get_tool(self, tool_name: str) -> Optional[BaseTool]:
        """Get a tool instance by name with error handling"""
        tool = self.tools.get(tool_name.lower())
        if tool is None:
            logger.warning(f"[ToolFactory] Tool not found: {tool_name}")
            return None
        return tool
    
    def list_tools(self) -> List[str]:
        """List available tools"""
        return list(self.tools.keys())
    
    def get_tool_stats(self) -> Dict[str, Any]:
        """Get statistics for all tools"""
        stats = {}
        for tool_name, tool in self.tools.items():
            stats[tool_name] = tool.get_stats()
        return stats
    
    def execute_safe(
        self, 
        tool_name: str, 
        params: Dict[str, Any],
        fallback_response: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute a tool with automatic fallback to demo responses.
        
        Args:
            tool_name: Name of the tool
            params: Parameters for the tool
            fallback_response: Optional fallback text if tool fails
        
        Returns:
            Tool execution result with fallback support
        """
        tool = self.get_tool(tool_name)
        
        if tool is None:
            logger.warning(f"[ToolFactory] Tool {tool_name} not available, using fallback")
            return {
                "status": "unavailable",
                "stdout": fallback_response or f"Tool {tool_name} not available",
                "stderr": f"{tool_name} not installed",
                "return_code": 127,
                "error_message": f"Tool not found: {tool_name}"
            }
        
        try:
            result = tool.execute(params)
            
            # Log execution result
            if result.get("status") == "success":
                logger.info(f"[{tool_name}] Execution successful")
            else:
                logger.warning(f"[{tool_name}] Execution status: {result.get('status')}")
            
            return result
            
        except Exception as e:
            logger.error(f"[{tool_name}] Unexpected error: {e}")
            return {
                "status": "error",
                "stdout": "",
                "stderr": str(e),
                "return_code": 1,
                "error_message": f"Unexpected error: {str(e)}"
            }

