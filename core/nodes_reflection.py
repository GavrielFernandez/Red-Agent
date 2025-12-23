"""
Reflection node - Analyzes execution results and decides on next steps
Core logic: Success? Continue to next step. Failure? Retry or pivot strategy.
"""

import logging
import json
from typing import Optional
from datetime import datetime

from ..core.state import AgentState, ReflectionEntry, ExecutionStatus
from ..config.config import config
from ..prompts.system_prompts import get_reflection_prompt

logger = logging.getLogger(__name__)

class ReflectionNode:
    """
    Self-reflection mechanism for error recovery and strategy adjustment.
    
    Responsibilities:
    1. Analyze last tool execution (success/failure)
    2. Determine if we should:
       a) Continue to next step
       b) Retry with modified parameters
       c) Change strategy entirely
    3. Track retry attempts and learned patterns
    4. Prevent infinite retry loops
    """
    
    def __init__(self, llm):
        self.llm = llm
    
    def invoke(self, state: AgentState) -> AgentState:
        """
        Main reflection loop.
        """
        
        logger.info(f"[Reflection] Analyzing execution results...")
        
        if not state["last_execution"]:
            logger.warning("[Reflection] No execution to reflect on")
            return state
        
        execution = state["last_execution"]
        
        # Step 1: Determine success/failure
        success = self._was_successful(execution)
        logger.debug(f"Execution success: {success}")
        
        # Step 2: Generate reflection using LLM
        reflection_prompt = get_reflection_prompt(state)
        
        try:
            llm_reflection = self.llm.invoke(reflection_prompt)
            reflection_text = llm_reflection.content if hasattr(llm_reflection, 'content') else str(llm_reflection)
        except Exception as e:
            logger.error(f"LLM reflection call failed: {e}")
            reflection_text = f"Error in reflection: {str(e)}"
        
        # Step 3: Parse reflection for key decisions
        should_retry, confidence, next_action = self._parse_reflection(reflection_text, success, state)
        
        # Step 4: Check retry limits
        tool_name = execution["tool_name"]
        if tool_name not in state["retry_strategies"]:
            state["retry_strategies"][tool_name] = []
        
        retry_count = len(state["retry_strategies"][tool_name])
        max_retries = config.tools.max_retries
        
        if retry_count >= max_retries:
            should_retry = False
            logger.warning(f"Max retries ({max_retries}) reached for tool: {tool_name}")
        
        # Step 5: Store reflection entry
        reflection: ReflectionEntry = {
            "step_number": state["loop_count"],
            "executed_action": tool_name,
            "observation": execution["stdout"][:200] if execution["stdout"] else execution["stderr"][:200],
            "reflection": reflection_text[:500],
            "confidence": confidence,
            "should_retry": should_retry,
            "next_action_suggestion": next_action,
            "timestamp": datetime.now().timestamp()
        }
        
        state["reflections"].append(reflection)
        state["last_reflection"] = reflection
        
        logger.info(f"[Reflection] Confidence: {confidence:.2f} | Should retry: {should_retry} | "
                   f"Next action: {next_action}")
        
        # Step 6: Make decision
        if not success:
            if should_retry and retry_count < max_retries:
                # Retry with different parameters
                logger.info(f"[Reflection] Retrying {tool_name} (attempt {retry_count + 1}/{max_retries})")
                state["retry_strategies"][tool_name].append(next_action or "parameter_adjustment")
                state["should_continue"] = True
                # The parsed_action and parsed_action_input will be modified by next reasoning cycle
            else:
                # Give up on this tool, move forward
                logger.info(f"[Reflection] Moving forward despite failure of {tool_name}")
                state["should_continue"] = True
                state["failed_attempts"] = 0  # Reset counter
        else:
            # Success! Continue normally
            logger.info(f"[Reflection] Tool succeeded. Continuing execution plan.")
            state["should_continue"] = True
            state["failed_attempts"] = 0
        
        # Step 7: Check termination conditions
        if state["loop_count"] >= state["max_loops"]:
            logger.info("[Reflection] Max reasoning loops reached. Terminating.")
            state["should_continue"] = False
            state["termination_reason"] = f"Reached max loops ({state['max_loops']})"
        
        if state["failed_attempts"] > config.agent.max_reflection_loops:
            logger.warning("[Reflection] Too many consecutive failures. Terminating.")
            state["should_continue"] = False
            state["termination_reason"] = f"Too many failures ({state['failed_attempts']})"
        
        return state
    
    def _was_successful(self, execution: dict) -> bool:
        """Determine if tool execution was successful"""
        
        # Success criteria:
        # 1. return_code == 0
        # 2. status == SUCCESS or PARTIAL
        # 3. No critical errors in stderr
        
        if execution["return_code"] == 0:
            return True
        
        if execution["status"] in [ExecutionStatus.SUCCESS, ExecutionStatus.PARTIAL]:
            return True
        
        if execution["status"] in [ExecutionStatus.FAILED, ExecutionStatus.ERROR]:
            return False
        
        return False
    
    def _parse_reflection(self, reflection_text: str, success: bool, state: AgentState) -> tuple:
        """
        Extract key information from LLM reflection.
        Returns: (should_retry: bool, confidence: float, next_action: str)
        """
        
        try:
            # Default values
            should_retry = not success
            confidence = 0.5
            next_action = "investigate_further"
            
            # Try to parse JSON response if LLM returns structured output
            if reflection_text.startswith("{"):
                try:
                    parsed = json.loads(reflection_text)
                    should_retry = parsed.get("should_retry", should_retry)
                    confidence = float(parsed.get("confidence", confidence))
                    next_action = parsed.get("next_action", next_action)
                except json.JSONDecodeError:
                    pass
            
            # Extract confidence from text patterns
            if "confidence" in reflection_text.lower():
                import re
                conf_match = re.search(r"confidence[:\s]+(\d+(?:\.\d+)?)", reflection_text, re.IGNORECASE)
                if conf_match:
                    try:
                        confidence = float(conf_match.group(1)) / 100 if float(conf_match.group(1)) > 1 else float(conf_match.group(1))
                    except ValueError:
                        pass
            
            return (should_retry, confidence, next_action)
        
        except Exception as e:
            logger.error(f"Error parsing reflection: {e}")
            return (not success, 0.5, "investigate_further")
