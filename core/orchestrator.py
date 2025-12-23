"""
Main LangGraph orchestration - ReAct loop with reflection
"""

from langgraph.graph import StateGraph
from typing import Literal
import logging

from .state import AgentState, create_initial_state
from .nodes_reasoning import ReasoningNode
from .nodes_execution import ExecutionNode
from .nodes_reflection import ReflectionNode
from ..memory.rag import RAGManager
from ..config.config import config

logger = logging.getLogger(__name__)

class RedAgentOrchestrator:
    """
    Main orchestrator for The Red Agent.
    Coordinates the ReAct loop: Reasoning -> Execution -> Reflection
    """
    
    def __init__(self, llm, rag_manager: RAGManager):
        """
        Initialize the agent with LLM and memory.
        
        Args:
            llm: LangChain LLM instance (e.g., Ollama Llama-3)
            rag_manager: ChromaDB RAG instance
        """
        
        self.llm = llm
        self.rag_manager = rag_manager
        
        # Initialize nodes
        self.reasoning_node = ReasoningNode(llm, rag_manager)
        self.execution_node = ExecutionNode()
        self.reflection_node = ReflectionNode(llm)
        
        # Build the graph
        self.graph = self._build_graph()
        self.compiled_graph = None
    
    def _build_graph(self):
        """
        Build the LangGraph workflow.
        
        Flow:
        reasoning -> should_execute? -> execution -> reflection -> should_continue?
        """
        
        graph = StateGraph(AgentState)
        
        # Add nodes
        graph.add_node("reasoning", self.reasoning_node.invoke)
        graph.add_node("execution", self.execution_node.invoke)
        graph.add_node("reflection", self.reflection_node.invoke)
        graph.add_node("end", self._end_node)
        
        # Add edges
        graph.set_entry_point("reasoning")
        
        # Reasoning -> Execution (always, unless invalid action)
        graph.add_edge("reasoning", "execution")
        
        # Execution -> Reflection (always)
        graph.add_edge("execution", "reflection")
        
        # Reflection -> Decision
        graph.add_conditional_edges(
            "reflection",
            self._should_continue,
            {
                "continue": "reasoning",
                "end": "end"
            }
        )
        
        graph.set_finish_point("end")
        
        return graph
    
    def _should_continue(self, state: AgentState) -> Literal["continue", "end"]:
        """
        Conditional logic: Should we continue the ReAct loop?
        
        Conditions to stop:
        1. should_continue == False
        2. Loop count >= max_loops
        3. Too many failures
        4. Target fully exploited
        """
        
        if not state["should_continue"]:
            return "end"
        
        if state["loop_count"] >= state["max_loops"]:
            logger.info("Max loops reached")
            return "end"
        
        return "continue"
    
    def _end_node(self, state: AgentState) -> AgentState:
        """
        End node - prepare final state for reporting
        """
        
        logger.info(f"\n{'='*60}")
        logger.info("RED AGENT EXECUTION COMPLETED")
        logger.info(f"{'='*60}")
        logger.info(f"Target: {state['target']}")
        logger.info(f"Total Loops: {state['loop_count']}")
        logger.info(f"Total Executions: {state['total_executions']}")
        logger.info(f"Vulnerabilities Found: {len(state['vulnerabilities'])}")
        logger.info(f"Termination Reason: {state['termination_reason']}")
        logger.info(f"{'='*60}\n")
        
        return state
    
    def compile(self):
        """Compile the graph for execution"""
        self.compiled_graph = self.graph.compile()
        return self.compiled_graph
    
    def run(self, target: str, target_type: str = "ip", target_description: str = "") -> AgentState:
        """
        Run the agent on a target.
        
        Args:
            target: IP address or URL
            target_type: "ip" or "url"
            target_description: Additional context
        
        Returns:
            Final AgentState with all findings
        """
        
        if not self.compiled_graph:
            self.compile()
        
        # Initialize state
        initial_state = create_initial_state(target, target_type, config.agent.max_reasoning_steps)
        initial_state["target_description"] = target_description
        
        logger.info(f"\n{'='*60}")
        logger.info("RED AGENT STARTING")
        logger.info(f"{'='*60}")
        logger.info(f"Target: {target} ({target_type})")
        logger.info(f"Max Loops: {initial_state['max_loops']}")
        logger.info(f"{'='*60}\n")
        
        # Execute the graph
        try:
            final_state = self.compiled_graph.invoke(initial_state)
            return final_state
        except Exception as e:
            logger.error(f"Graph execution failed: {e}")
            initial_state["errors"].append({
                "type": "graph_execution_error",
                "message": str(e),
                "timestamp": ""
            })
            initial_state["should_continue"] = False
            initial_state["termination_reason"] = f"Execution error: {str(e)}"
            return initial_state
