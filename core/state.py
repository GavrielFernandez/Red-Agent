"""
AgentState Definition for LangGraph
Complete TypedDict with all necessary fields for ReAct loop with Self-Reflection
"""

from typing import TypedDict, Optional, List, Dict, Any
from enum import Enum

class ExecutionStatus(str, Enum):
    """Execution status for tools"""
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    ERROR = "error"
    SKIPPED = "skipped"

class ToolExecution(TypedDict):
    """Single tool execution record"""
    tool_name: str
    tool_args: Dict[str, Any]
    stdout: str
    stderr: str
    return_code: int
    execution_time: float
    status: ExecutionStatus
    error_message: Optional[str]
    retry_count: int
    timestamp: float

class ReflectionEntry(TypedDict):
    """Reflection analysis after tool execution"""
    step_number: int
    executed_action: str
    observation: str  # Tool output summary
    reflection: str  # LLM's analysis of success/failure
    confidence: float  # 0.0 - 1.0
    should_retry: bool
    next_action_suggestion: Optional[str]
    timestamp: float

class VulnerabilityFinding(TypedDict):
    """Discovered vulnerability"""
    vulnerability_id: str
    type: str  # "sql_injection", "weak_credentials", "exposed_port", etc.
    severity: str  # "critical", "high", "medium", "low"
    location: str  # Port, endpoint, service
    description: str
    evidence: str
    exploitation_status: str  # "identified", "exploited", "failed"
    confidence: float

class AgentState(TypedDict):
    """
    Complete state for The Red Agent.
    Manages: History, Plans, Execution, Reflection, and Findings.
    """
    
    # === Input & Target Information ===
    target: str  # IP address or URL
    target_type: str  # "ip" or "url"
    target_description: str  # User-provided context
    
    # === Reasoning & Planning ===
    reasoning_history: List[str]  # Chain of thoughts
    current_plan: str  # High-level attack strategy
    plan_steps: List[str]  # Broken-down steps
    current_step_index: int  # Which step we're on
    
    # === Execution Tracking ===
    execution_history: List[ToolExecution]  # All tool runs
    last_execution: Optional[ToolExecution]  # Most recent tool execution
    failed_attempts: int  # Count of failed tool runs in current loop
    total_executions: int  # Total tools run so far
    
    # === Reflection & Learning ===
    reflections: List[ReflectionEntry]  # Analysis after each execution
    last_reflection: Optional[ReflectionEntry]
    retry_strategies: Dict[str, List[str]]  # tool_name -> [strategies tried]
    
    # === Findings ===
    vulnerabilities: List[VulnerabilityFinding]  # Discovered issues
    exploited_services: List[str]  # Services we've successfully exploited
    
    # === Memory & Context ===
    relevant_context: List[str]  # Retrieved from ChromaDB RAG
    scanned_ports: Dict[str, str]  # port -> service mapping
    open_services: List[Dict[str, Any]]  # Detailed service info
    
    # === Control Flow ===
    loop_count: int  # Number of ReAct cycles completed
    max_loops: int  # Maximum allowed cycles
    should_continue: bool  # Continue to next cycle?
    termination_reason: Optional[str]  # Why did we stop?
    
    # === LLM Interaction ===
    last_llm_response: Optional[str]  # Raw LLM output
    parsed_action: Optional[str]  # Extracted action from LLM
    parsed_action_input: Optional[Dict[str, Any]]  # Tool arguments
    
    # === Error Tracking ===
    errors: List[Dict[str, Any]]  # [{type, message, timestamp, context}]
    warnings: List[Dict[str, Any]]  # [{level, message, timestamp}]
    
    # === Reporting ===
    report_data: Dict[str, Any]  # Compiled for PDF generation
    summary: str  # Executive summary

def create_initial_state(target: str, target_type: str = "ip", max_loops: int = 15) -> AgentState:
    """
    Factory function to create initial AgentState for a new target
    
    Args:
        target: IP address or URL
        target_type: "ip" or "url"
        max_loops: Maximum reasoning cycles
    
    Returns:
        Initialized AgentState
    """
    return AgentState(
        target=target,
        target_type=target_type,
        target_description="",
        reasoning_history=[],
        current_plan="",
        plan_steps=[],
        current_step_index=0,
        execution_history=[],
        last_execution=None,
        failed_attempts=0,
        total_executions=0,
        reflections=[],
        last_reflection=None,
        retry_strategies={},
        vulnerabilities=[],
        exploited_services=[],
        relevant_context=[],
        scanned_ports={},
        open_services=[],
        loop_count=0,
        max_loops=max_loops,
        should_continue=True,
        termination_reason=None,
        last_llm_response=None,
        parsed_action=None,
        parsed_action_input=None,
        errors=[],
        warnings=[],
        report_data={},
        summary="",
    )
