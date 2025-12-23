"""
Execution node - Runs the tool decided by reasoning node
Handles subprocess execution, timeout, error capture
"""

import subprocess
import time
import logging
import json
from typing import Optional, Dict, Any
from datetime import datetime

from ..core.state import AgentState, ToolExecution, ExecutionStatus
from ..tools.tool_factory import ToolFactory
from ..config.config import config

logger = logging.getLogger(__name__)

class ExecutionNode:
    """
    Executes the tool action decided by ReasoningNode.
    
    Responsibilities:
    1. Route to correct tool wrapper
    2. Execute with timeout protection
    3. Capture stdout/stderr/return_code
    4. Store execution record
    5. Handle errors gracefully
    """
    
    def __init__(self):
        self.tool_factory = ToolFactory()
        self.execution_count = 0
    
    def invoke(self, state: AgentState) -> AgentState:
        """
        Execute the parsed action.
        """
        
        action = state.get("parsed_action")
        action_input = state.get("parsed_action_input", {})
        
        if not action:
            logger.error("No action to execute")
            state["errors"].append({
                "type": "execution_error",
                "message": "No action parsed for execution",
                "timestamp": datetime.now().isoformat()
            })
            state["should_continue"] = False
            return state
        
        logger.info(f"[Execution] Running tool: {action} with input: {action_input}")
        
        # Get tool executor
        tool = self.tool_factory.get_tool(action)
        if tool is None:
            logger.error(f"No tool found for action: {action}")
            state["errors"].append({
                "type": "tool_not_found",
                "message": f"Tool '{action}' not implemented",
                "timestamp": datetime.now().isoformat()
            })
            state["should_continue"] = False
            return state
        
        # Execute tool
        start_time = time.time()
        try:
            result = tool.execute(action_input)
            execution_time = time.time() - start_time
        except subprocess.TimeoutExpired as e:
            execution_time = time.time() - start_time
            logger.error(f"Tool timeout after {execution_time}s: {action}")
            result = {
                "stdout": "",
                "stderr": f"TIMEOUT: Tool execution exceeded timeout after {execution_time}s",
                "return_code": 124,  # Timeout exit code
                "status": ExecutionStatus.FAILED
            }
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Tool execution error: {e}")
            result = {
                "stdout": "",
                "stderr": f"ERROR: {str(e)}",
                "return_code": 1,
                "status": ExecutionStatus.ERROR
            }
        
        # Create execution record
        execution: ToolExecution = {
            "tool_name": action,
            "tool_args": action_input,
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "return_code": result.get("return_code", -1),
            "execution_time": execution_time,
            "status": result.get("status", ExecutionStatus.FAILED),
            "error_message": result.get("error_message"),
            "retry_count": state["failed_attempts"],
            "timestamp": datetime.now().timestamp()
        }
        
        # Update state
        state["execution_history"].append(execution)
        state["last_execution"] = execution
        state["total_executions"] += 1
        self.execution_count += 1
        
        logger.info(f"[Execution] Tool '{action}' completed with status: {execution['status']} "
                   f"(return_code: {execution['return_code']}, time: {execution_time:.2f}s)")
        
        if execution["status"] == ExecutionStatus.FAILED or execution["return_code"] != 0:
            state["failed_attempts"] += 1
            logger.warning(f"Tool execution failed. Failed attempts: {state['failed_attempts']}")
        else:
            state["failed_attempts"] = 0  # Reset on success
        
        return state
