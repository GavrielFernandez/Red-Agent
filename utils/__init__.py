# utils/__init__.py
# Utility functions and helpers for The Red Agent

import logging
from typing import List, Dict, Any

def setup_logging(log_file: str = "red_agent.log") -> None:
    """Configure logging for the agent"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

def extract_ports_from_nmap(nmap_output: str) -> Dict[str, str]:
    """
    Parse nmap output and extract open ports.
    Returns: {port: service} mapping
    """
    ports = {}
    for line in nmap_output.split('\n'):
        if 'open' in line.lower():
            parts = line.split()
            if parts:
                port = parts[0].split('/')[0]
                service = parts[-1] if len(parts) > 1 else 'unknown'
                ports[port] = service
    return ports

def extract_databases_from_sqlmap(sqlmap_output: str) -> List[str]:
    """
    Parse sqlmap output and extract database names.
    """
    databases = []
    in_db_section = False
    for line in sqlmap_output.split('\n'):
        if 'available databases' in line.lower():
            in_db_section = True
        elif in_db_section and line.strip():
            if line.strip().startswith('['):
                databases.append(line.strip().strip('[]'))
    return databases

def is_valid_target(target: str, target_type: str) -> bool:
    """
    Validate target format.
    """
    import re
    if target_type == "ip":
        # Basic IPv4 validation
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, target))
    elif target_type == "url":
        # Basic URL validation
        url_pattern = r'^https?://.+'
        return bool(re.match(url_pattern, target))
    return False

__all__ = [
    "setup_logging",
    "extract_ports_from_nmap",
    "extract_databases_from_sqlmap",
    "is_valid_target"
]
