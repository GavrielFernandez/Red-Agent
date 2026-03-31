"""
RedAgent Multi-Agent Swarm Architecture
=======================================

Specialized autonomous agents working in coordination:

- CommandControl: Master orchestrator, delegates and coordinates
- ReconAgent: OSINT, reconnaissance, asset discovery  
- ExploitAgent: Vulnerability exploitation specialist
- PostExploitAgent: Privilege escalation, lateral movement
- PayloadAgent: Custom payload generation and obfuscation
- EvasionAgent: WAF/IDS bypass and detection evasion

Each agent can operate independently or as part of a swarm.
"""

from .base_agent import BaseAgent, AgentMessage, AgentStatus
from .command_control import CommandControl
from .recon_agent import ReconAgent
from .exploit_agent import ExploitAgent

__all__ = [
    'BaseAgent',
    'AgentMessage', 
    'AgentStatus',
    'CommandControl',
    'ReconAgent',
    'ExploitAgent'
]
