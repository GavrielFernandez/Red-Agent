"""
Core reasoning node - Decides what action to take next
Uses ReAct format: Thought -> Action -> Observation
"""

import re
import json
import logging
from typing import Optional, Dict, Any
from datetime import datetime
from langchain_core.language_models import BaseLLM

from .state import AgentState, ExecutionStatus
from ..memory.rag import RAGManager
from ..prompts.system_prompts import get_reasoning_prompt, REACT_FORMAT_INSTRUCTION
from ..config.config import config

logger = logging.getLogger(__name__)

class ReasoningNode:
    """
    Responsible for:
    1. Deciding the next action (tool to execute)
    2. Generating reasoning (Thought)
    3. Parsing LLM output in ReAct format
    4. Preventing hallucination of non-existent tools
    """
    
    VALID_TOOLS = {
        "nmap": "Network scanning and port mapping",
        "sqlmap": "SQL injection testing",
        "curl": "HTTP requests and API testing",
        "hydra": "Credential brute-forcing",
        "analyze_scan": "Parse nmap results for vulnerabilities",
        "check_memory": "Retrieve relevant past findings from ChromaDB",
        "formulate_plan": "Break down attack strategy into steps"
    }
    
    def __init__(self, llm: BaseLLM, rag_manager: RAGManager):
        self.llm = llm
        self.rag_manager = rag_manager
    
    def invoke(self, state: AgentState) -> AgentState:
        """
        Main reasoning loop:
        1. Retrieve relevant context from memory
        2. Build prompt with target, history, and ReAct instructions
        3. Call LLM
        4. Parse response into Action/Input
        5. Validate tool exists
        6. Return updated state
        """
        
        logger.info(f"[Reasoning] Starting cycle {state['loop_count'] + 1}/{state['max_loops']}")
        
        # Step 1: Retrieve relevant context from ChromaDB
        if state["target"]:
            relevant_docs = self.rag_manager.retrieve(
                query=f"vulnerabilities exploits for {state['target']}",
                k=config.memory.k_relevant_docs
            )
            state["relevant_context"] = relevant_docs
            logger.debug(f"Retrieved {len(relevant_docs)} relevant documents from memory")
        
        # Step 2: Build the prompt
        system_prompt = get_reasoning_prompt(state, self.VALID_TOOLS)
        
        # Step 3: Call LLM with streaming
        logger.info("[Reasoning] Calling LLM...")
        try:
            response = self.llm.invoke(system_prompt)
            state["last_llm_response"] = response.content if hasattr(response, 'content') else str(response)
        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            state["errors"].append({
                "type": "llm_error",
                "message": str(e),
                "timestamp": datetime.now().isoformat(),
                "loop": state["loop_count"]
            })
            state["should_continue"] = False
            state["termination_reason"] = f"LLM failure: {str(e)}"
            return state
        
        logger.debug(f"LLM Response:\n{state['last_llm_response']}")
        
        # Step 4: Parse the response in ReAct format
        parsed = self._parse_react_response(state["last_llm_response"])
        
        if parsed is None:
            logger.error("Failed to parse LLM response")
            state["errors"].append({
                "type": "parse_error",
                "message": "Could not extract Action and Action Input from LLM response",
                "timestamp": datetime.now().isoformat(),
                "loop": state["loop_count"],
                "response": state["last_llm_response"]
            })
            state["should_continue"] = False
            state["termination_reason"] = "Failed to parse LLM output"
            return state
        
        thought, action, action_input = parsed
        
        # Store in state
        state["reasoning_history"].append(thought)
        state["parsed_action"] = action
        state["parsed_action_input"] = action_input
        
        # Step 5: Validate action
        if action not in self.VALID_TOOLS:
            logger.error(f"Invalid action: {action}. Valid tools: {list(self.VALID_TOOLS.keys())}")
            state["errors"].append({
                "type": "validation_error",
                "message": f"Attempted to use non-existent tool: {action}",
                "valid_tools": list(self.VALID_TOOLS.keys()),
                "timestamp": datetime.now().isoformat()
            })
            
            # Force reflection to correct the error
            state["should_continue"] = True  # Will go to reflection, not execution
            state["termination_reason"] = None
            state["failed_attempts"] += 1
            
        logger.info(f"[Reasoning] Decided action: {action} with input: {action_input}")
        state["loop_count"] += 1
        
        return state
    
    def _parse_react_response(self, response: str) -> Optional[tuple]:
        """
        Parse ReAct format response.
        Expected format:
        Thought: <reasoning>
        Action: <tool_name>
        Action Input: <json_or_plain_input>
        
        Returns:
            (thought, action, action_input) or None if parsing failed
        """
        
        try:
            # Extract Thought
            thought_match = re.search(
                r"Thought:\s*(.*?)(?=\nAction:|$)",
                response,
                re.IGNORECASE | re.DOTALL
            )
            thought = thought_match.group(1).strip() if thought_match else ""
            
            # Extract Action
            action_match = re.search(
                r"Action:\s*(\w+)",
                response,
                re.IGNORECASE
            )
            if not action_match:
                logger.error("Could not extract Action from response")
                return None
            action = action_match.group(1).lower()
            
            # Extract Action Input
            action_input_match = re.search(
                r"Action\s+Input:\s*(.*?)(?=\n\n|$)",
                response,
                re.IGNORECASE | re.DOTALL
            )
            action_input_str = action_input_match.group(1).strip() if action_input_match else "{}"
            
            # Try to parse as JSON, fallback to dict with 'input' key
            try:
                action_input = json.loads(action_input_str)
            except json.JSONDecodeError:
                action_input = {"input": action_input_str}
            
            logger.debug(f"Parsed - Thought: {thought[:100]}... | Action: {action} | Input: {action_input}")
            return (thought, action, action_input)
        
        except Exception as e:
            logger.error(f"Error parsing ReAct response: {e}")
            return None
