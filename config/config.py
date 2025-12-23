"""
Configuration module for The Red Agent
Centralized settings for LLM, tools, memory, and execution parameters
"""

from dataclasses import dataclass
from typing import Optional

@dataclass
class LLMConfig:
    """Llama-3 Configuration"""
    model_name: str = "llama2"  # Ollama model name
    base_url: str = "http://localhost:11434"
    temperature: float = 0.3  # Lower temp for consistency
    top_p: float = 0.9
    top_k: int = 40
    max_tokens: int = 2048
    context_window: int = 8192

@dataclass
class ToolConfig:
    """Tool-specific timeout and retry settings"""
    nmap_timeout: int = 300
    sqlmap_timeout: int = 600
    hydra_timeout: int = 600
    curl_timeout: int = 30
    
    # Retry mechanism
    max_retries: int = 3
    retry_backoff_factor: float = 1.5

@dataclass
class MemoryConfig:
    """ChromaDB Configuration"""
    db_path: str = "./chroma_db"
    collection_name: str = "red_agent_context"
    embedding_model: str = "all-MiniLM-L6-v2"
    chunk_size: int = 512
    chunk_overlap: int = 128
    k_relevant_docs: int = 5

@dataclass
class AgentConfig:
    """Agent execution parameters"""
    max_reasoning_steps: int = 15
    max_reflection_loops: int = 3
    reflection_threshold: float = 0.6  # Confidence threshold for accepting results
    target_timeout: int = 3600  # Max time per target (seconds)
    enable_detailed_logging: bool = True
    log_dir: str = "./logs"

class RedAgentConfig:
    """Master configuration for The Red Agent"""
    
    def __init__(self):
        self.llm = LLMConfig()
        self.tools = ToolConfig()
        self.memory = MemoryConfig()
        self.agent = AgentConfig()
    
    def to_dict(self):
        """Convert to dictionary for logging/debugging"""
        return {
            "llm": self.llm.__dict__,
            "tools": self.tools.__dict__,
            "memory": self.memory.__dict__,
            "agent": self.agent.__dict__,
        }

# Global config instance
config = RedAgentConfig()
