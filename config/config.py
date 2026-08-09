"""
Configuration module for The Red Agent
Centralized settings for LLM, tools, memory, dashboard, and execution parameters
Supports environment variable overrides for deployment
"""

from dataclasses import dataclass
from typing import Optional
import os
from pathlib import Path

# ============================================================================
# LLM Configuration
# ============================================================================

@dataclass
class LLMConfig:
    """Ollama/LLM Configuration"""
    model_name: str = os.getenv("REDAGENT_LLM_MODEL", "phi")
    base_url: str = os.getenv("REDAGENT_LLM_URL", "http://localhost:11434")
    temperature: float = float(os.getenv("REDAGENT_LLM_TEMP", "0.3"))
    top_p: float = float(os.getenv("REDAGENT_LLM_TOP_P", "0.9"))
    top_k: int = int(os.getenv("REDAGENT_LLM_TOP_K", "40"))
    max_tokens: int = int(os.getenv("REDAGENT_LLM_MAX_TOKENS", "2048"))
    context_window: int = int(os.getenv("REDAGENT_LLM_CONTEXT", "8192"))
    timeout: int = int(os.getenv("REDAGENT_LLM_TIMEOUT", "600"))  # API timeout in seconds
    enable_fallback: bool = os.getenv("REDAGENT_LLM_FALLBACK", "true").lower() == "true"

# ============================================================================
# Tool Configuration
# ============================================================================

@dataclass
class ToolConfig:
    """Tool-specific timeout and retry settings"""
    nmap_timeout: int = int(os.getenv("REDAGENT_NMAP_TIMEOUT", "120"))
    sqlmap_timeout: int = int(os.getenv("REDAGENT_SQLMAP_TIMEOUT", "60"))
    hydra_timeout: int = int(os.getenv("REDAGENT_HYDRA_TIMEOUT", "180"))
    curl_timeout: int = int(os.getenv("REDAGENT_CURL_TIMEOUT", "20"))
    
    # Retry mechanism
    max_retries: int = int(os.getenv("REDAGENT_TOOL_RETRIES", "2"))
    retry_backoff_factor: float = float(os.getenv("REDAGENT_TOOL_BACKOFF", "1.5"))
    
    # Tool paths (for security, can override system defaults)
    nmap_path: str = os.getenv("REDAGENT_NMAP_PATH", "nmap")
    sqlmap_path: str = os.getenv("REDAGENT_SQLMAP_PATH", "sqlmap")
    curl_path: str = os.getenv("REDAGENT_CURL_PATH", "curl")
    hydra_path: str = os.getenv("REDAGENT_HYDRA_PATH", "hydra")

    # Plugin loading (semicolon-separated absolute or relative directories)
    plugin_paths: str = os.getenv("REDAGENT_TOOL_PLUGIN_PATHS", "")

# ============================================================================
# Memory Configuration
# ============================================================================

@dataclass
class MemoryConfig:
    """ChromaDB Configuration for learning and context"""
    db_path: str = os.getenv("REDAGENT_MEMORY_PATH", "./chroma_db")
    collection_name: str = os.getenv("REDAGENT_MEMORY_COLLECTION", "red_agent_context")
    embedding_model: str = os.getenv("REDAGENT_EMBEDDING_MODEL", "all-MiniLM-L6-v2")
    chunk_size: int = int(os.getenv("REDAGENT_CHUNK_SIZE", "512"))
    chunk_overlap: int = int(os.getenv("REDAGENT_CHUNK_OVERLAP", "128"))
    k_relevant_docs: int = int(os.getenv("REDAGENT_K_DOCS", "5"))
    enable_learning: bool = os.getenv("REDAGENT_ENABLE_LEARNING", "true").lower() == "true"

# ============================================================================
# Dashboard/Flask Configuration
# ============================================================================

@dataclass
class DashboardConfig:
    """Flask Dashboard Configuration"""
    host: str = os.getenv("REDAGENT_DASHBOARD_HOST", "0.0.0.0")
    port: int = int(os.getenv("REDAGENT_DASHBOARD_PORT", "5000"))
    debug: bool = os.getenv("REDAGENT_DASHBOARD_DEBUG", "false").lower() == "true"
    secret_key: str = os.getenv("REDAGENT_SECRET_KEY", "default-insecure-key")  # Change in production!
    cors_origins: str = os.getenv("REDAGENT_CORS_ORIGINS", "*")
    
    # Job management
    max_concurrent_jobs: int = int(os.getenv("REDAGENT_MAX_JOBS", "5"))
    job_timeout: int = int(os.getenv("REDAGENT_JOB_TIMEOUT", "3600"))  # seconds
    keep_job_history: int = int(os.getenv("REDAGENT_KEEP_HISTORY", "50"))  # Number of jobs to retain
    
    # Rate limiting
    enable_rate_limiting: bool = os.getenv("REDAGENT_RATE_LIMIT", "true").lower() == "true"
    requests_per_minute: int = int(os.getenv("REDAGENT_RPM_LIMIT", "60"))

# ============================================================================
# Agent Configuration
# ============================================================================

@dataclass
class AgentConfig:
    """Agent execution parameters"""
    max_reasoning_steps: int = int(os.getenv("REDAGENT_MAX_STEPS", "15"))
    max_reflection_loops: int = int(os.getenv("REDAGENT_MAX_LOOPS", "3"))
    reflection_threshold: float = float(os.getenv("REDAGENT_CONFIDENCE_THRESHOLD", "0.6"))
    target_timeout: int = int(os.getenv("REDAGENT_TARGET_TIMEOUT", "3600"))  # seconds
    
    # Attack configuration
    run_sql_injection: bool = os.getenv("REDAGENT_RUN_SQLI", "true").lower() == "true"
    run_xss: bool = os.getenv("REDAGENT_RUN_XSS", "true").lower() == "true"
    run_command_injection: bool = os.getenv("REDAGENT_RUN_CMD", "true").lower() == "true"
    run_path_traversal: bool = os.getenv("REDAGENT_RUN_PATH", "true").lower() == "true"
    run_ldap_injection: bool = os.getenv("REDAGENT_RUN_LDAP", "true").lower() == "true"
    run_xxe: bool = os.getenv("REDAGENT_RUN_XXE", "true").lower() == "true"
    run_header_injection: bool = os.getenv("REDAGENT_RUN_HEADER", "true").lower() == "true"
    run_brute_force: bool = os.getenv("REDAGENT_RUN_BRUTE", "true").lower() == "true"

# ============================================================================
# Logging Configuration
# ============================================================================

@dataclass
class LoggingConfig:
    """Logging Configuration"""
    log_dir: str = os.getenv("REDAGENT_LOG_DIR", "./logs")
    log_level: str = os.getenv("REDAGENT_LOG_LEVEL", "INFO")
    enable_file_logging: bool = os.getenv("REDAGENT_FILE_LOGGING", "true").lower() == "true"
    enable_console_logging: bool = os.getenv("REDAGENT_CONSOLE_LOGGING", "true").lower() == "true"
    max_log_size: int = int(os.getenv("REDAGENT_MAX_LOG_SIZE", "10485760"))  # 10MB
    backup_count: int = int(os.getenv("REDAGENT_LOG_BACKUPS", "5"))
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    detailed_logs: bool = os.getenv("REDAGENT_DETAILED_LOGS", "true").lower() == "true"

# ============================================================================
# Security Configuration
# ============================================================================

@dataclass
class SecurityConfig:
    """Security settings"""
    enable_auth: bool = os.getenv("REDAGENT_ENABLE_AUTH", "false").lower() == "true"
    api_key: Optional[str] = os.getenv("REDAGENT_API_KEY", None)
    require_https: bool = os.getenv("REDAGENT_REQUIRE_HTTPS", "true").lower() == "true"
    allowed_hosts: str = os.getenv("REDAGENT_ALLOWED_HOSTS", "localhost,127.0.0.1")
    enable_audit_log: bool = os.getenv("REDAGENT_AUDIT_LOG", "true").lower() == "true"
    sanitize_logs: bool = os.getenv("REDAGENT_SANITIZE_LOGS", "true").lower() == "true"

# ============================================================================
# Global Configuration Object
# ============================================================================

@dataclass
class Config:
    """Master configuration container"""
    llm: LLMConfig = None
    tools: ToolConfig = None
    memory: MemoryConfig = None
    dashboard: DashboardConfig = None
    agent: AgentConfig = None
    logging: LoggingConfig = None
    security: SecurityConfig = None
    
    # Meta settings
    environment: str = os.getenv("REDAGENT_ENV", "development")
    version: str = "1.0.0"
    debug: bool = os.getenv("REDAGENT_DEBUG", "false").lower() == "true"
    
    def __post_init__(self):
        """Initialize nested config objects"""
        self.llm = self.llm or LLMConfig()
        self.tools = self.tools or ToolConfig()
        self.memory = self.memory or MemoryConfig()
        self.dashboard = self.dashboard or DashboardConfig()
        self.agent = self.agent or AgentConfig()
        self.logging = self.logging or LoggingConfig()
        self.security = self.security or SecurityConfig()
        
        # Ensure log directory exists
        Path(self.logging.log_dir).mkdir(parents=True, exist_ok=True)

# ============================================================================
# Create global config instance
# ============================================================================

config = Config()

# ============================================================================
# Utility functions
# ============================================================================

def get_config() -> Config:
    """Get the global configuration instance"""
    return config

def print_config():
    """Print current configuration (safe - hides secrets)"""
    print("="*70)
    print("RED AGENT CONFIGURATION")
    print("="*70)
    print(f"Environment: {config.environment}")
    print(f"Debug: {config.debug}")
    print(f"Version: {config.version}")
    print()
    print("LLM:")
    print(f"  Model: {config.llm.model_name}")
    print(f"  URL: {config.llm.base_url}")
    print()
    print("Tools:")
    print(f"  Max Retries: {config.tools.max_retries}")
    print(f"  Tool Timeouts: Nmap={config.tools.nmap_timeout}s, "
          f"SQLMap={config.tools.sqlmap_timeout}s, Curl={config.tools.curl_timeout}s")
    print()
    print("Dashboard:")
    print(f"  Host: {config.dashboard.host}:{config.dashboard.port}")
    print(f"  Max Concurrent Jobs: {config.dashboard.max_concurrent_jobs}")
    print()
    print("Agent:")
    print(f"  Max Steps: {config.agent.max_reasoning_steps}")
    print(f"  Target Timeout: {config.agent.target_timeout}s")
    print()
    print("Logging:")
    print(f"  Log Level: {config.logging.log_level}")
    print(f"  Log Directory: {config.logging.log_dir}")
    print("="*70)

class RedAgentConfig(Config):
    """Backward-compatible alias for the canonical Config dataclass."""

    pass
