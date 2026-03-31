"""
Centralized Logging Utility for RedAgent
Provides structured logging, rotation, formatting, and audit trails
"""

import logging
import logging.handlers
from pathlib import Path
from datetime import datetime
import json
from typing import Dict, Any, Optional
from config.config import config

class RedAgentLogger:
    """Centralized logging with structured output"""
    
    # Logger instances cache
    _loggers: Dict[str, logging.Logger] = {}
    _audit_logger: Optional[logging.Logger] = None
    
    @classmethod
    def get_logger(cls, name: str) -> logging.Logger:
        """Get or create a logger for the given name"""
        if name in cls._loggers:
            return cls._loggers[name]
        
        logger = cls._setup_logger(name)
        cls._loggers[name] = logger
        return logger
    
    @classmethod
    def _setup_logger(cls, name: str) -> logging.Logger:
        """Setup a logger with file and console handlers"""
        logger = logging.getLogger(name)
        logger.setLevel(getattr(logging, config.logging.log_level))
        
        # Prevent duplicate handlers
        if logger.handlers:
            return logger
        
        # Formatter
        formatter = logging.Formatter(
            config.logging.log_format,
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Console Handler
        if config.logging.enable_console_logging:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(getattr(logging, config.logging.log_level))
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
        
        # File Handler with rotation
        if config.logging.enable_file_logging:
            log_dir = Path(config.logging.log_dir)
            log_dir.mkdir(parents=True, exist_ok=True)
            
            log_file = log_dir / f"{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=config.logging.max_log_size,
                backupCount=config.logging.backup_count
            )
            file_handler.setLevel(getattr(logging, config.logging.log_level))
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        return logger
    
    @classmethod
    def get_audit_logger(cls) -> logging.Logger:
        """Get the audit logger for security events"""
        if cls._audit_logger is None:
            cls._audit_logger = cls._setup_audit_logger()
        return cls._audit_logger
    
    @classmethod
    def _setup_audit_logger(cls) -> logging.Logger:
        """Setup dedicated audit logger"""
        audit_logger = logging.getLogger("redagent_audit")
        audit_logger.setLevel(logging.INFO)
        
        log_dir = Path(config.logging.log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        
        audit_file = log_dir / f"audit_{datetime.now().strftime('%Y%m%d')}.log"
        
        handler = logging.handlers.RotatingFileHandler(
            audit_file,
            maxBytes=config.logging.max_log_size,
            backupCount=config.logging.backup_count
        )
        
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        audit_logger.addHandler(handler)
        
        return audit_logger
    
    @staticmethod
    def log_audit_event(event_type: str, details: Dict[str, Any]) -> None:
        """Log an audit event (security, access, changes)"""
        if not config.security.enable_audit_log:
            return
        
        audit_logger = RedAgentLogger.get_audit_logger()
        
        # Sanitize sensitive data if enabled
        if config.security.sanitize_logs:
            details = RedAgentLogger._sanitize_dict(details)
        
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "details": details
        }
        
        audit_logger.info(json.dumps(event))
    
    @staticmethod
    def _sanitize_dict(data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive information from logs"""
        sensitive_keys = [
            "password", "token", "api_key", "secret", 
            "credential", "auth", "key", "username"
        ]
        
        sanitized = {}
        for key, value in data.items():
            key_lower = key.lower()
            if any(sens in key_lower for sens in sensitive_keys):
                sanitized[key] = "***REDACTED***"
            elif isinstance(value, dict):
                sanitized[key] = RedAgentLogger._sanitize_dict(value)
            else:
                sanitized[key] = value
        
        return sanitized
    
    @staticmethod
    def log_tool_execution(
        tool_name: str,
        params: Dict[str, Any],
        result: Dict[str, Any]
    ) -> None:
        """Log tool execution details"""
        logger = RedAgentLogger.get_logger("tools")
        
        logger.info(
            f"Tool: {tool_name} | Status: {result.get('status', 'unknown')} | "
            f"Return Code: {result.get('return_code', 'N/A')} | "
            f"Time: {result.get('execution_time', 'N/A'):.2f}s"
        )
    
    @staticmethod
    def log_assessment_start(job_id: str, target: str, target_type: str) -> None:
        """Log assessment start"""
        logger = RedAgentLogger.get_logger("assessment")
        logger.info(f"[{job_id}] Assessment started: {target} (type: {target_type})")
        
        RedAgentLogger.log_audit_event("assessment_start", {
            "job_id": job_id,
            "target": target,
            "target_type": target_type
        })
    
    @staticmethod
    def log_assessment_complete(
        job_id: str,
        target: str,
        vulnerabilities_found: int,
        duration: float
    ) -> None:
        """Log assessment completion"""
        logger = RedAgentLogger.get_logger("assessment")
        logger.info(
            f"[{job_id}] Assessment completed: {vulnerabilities_found} vulnerabilities "
            f"found in {duration:.1f}s"
        )
        
        RedAgentLogger.log_audit_event("assessment_complete", {
            "job_id": job_id,
            "target": target,
            "vulnerabilities_found": vulnerabilities_found,
            "duration_seconds": duration
        })
    
    @staticmethod
    def log_vulnerability(
        job_id: str,
        vuln_type: str,
        severity: str,
        location: str
    ) -> None:
        """Log vulnerability discovery"""
        logger = RedAgentLogger.get_logger("vulnerabilities")
        logger.warning(
            f"[{job_id}] {severity.upper()}: {vuln_type} at {location}"
        )
        
        RedAgentLogger.log_audit_event("vulnerability_found", {
            "job_id": job_id,
            "type": vuln_type,
            "severity": severity,
            "location": location
        })
    
    @staticmethod
    def log_api_request(
        endpoint: str,
        method: str,
        ip_address: str,
        status_code: int
    ) -> None:
        """Log API request"""
        logger = RedAgentLogger.get_logger("api")
        logger.info(f"{method} {endpoint} from {ip_address} - {status_code}")
    
    @staticmethod
    def log_error(logger_name: str, error_msg: str, exception: Exception = None) -> None:
        """Log an error with traceback if available"""
        logger = RedAgentLogger.get_logger(logger_name)
        
        if exception:
            logger.exception(error_msg)
        else:
            logger.error(error_msg)
        
        RedAgentLogger.log_audit_event("error", {
            "logger": logger_name,
            "message": error_msg,
            "exception_type": type(exception).__name__ if exception else None
        })


# Convenience function for quick access
def get_logger(name: str) -> logging.Logger:
    """Quick function to get a logger"""
    return RedAgentLogger.get_logger(name)
