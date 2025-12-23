"""
Main entry point for The Red Agent
"""

import logging
import sys
from pathlib import Path
import requests

from config.config import config
from core.orchestrator import RedAgentOrchestrator
from memory.rag import RAGManager
from reporting.report_generator import ReportGenerator

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Path(config.agent.log_dir) / 'red_agent.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class OllamaLLM:
    """Direct Ollama API wrapper"""
    def __init__(self, model_name="llama2", base_url="http://localhost:11434"):
        self.model_name = model_name
        self.base_url = base_url
        self.api_url = f"{base_url}/api/generate"
    
    def __call__(self, prompt: str, temperature=0.3, **kwargs) -> str:
        """Query Ollama LLM"""
        try:
            response = requests.post(
                self.api_url,
                json={
                    "model": self.model_name,
                    "prompt": prompt,
                    "stream": False,
                    "temperature": temperature
                },
                timeout=120
            )
            if response.status_code == 200:
                return response.json().get('response', '')
            else:
                logger.error(f"Ollama API error: {response.status_code}")
                return ""
        except Exception as e:
            logger.error(f"Error querying LLM: {e}")
            return ""

def initialize_agent():
    """Initialize The Red Agent with LLM and Memory"""
    
    logger.info("Initializing Red Agent...")
    
    # Initialize LLM (Llama2 via Ollama - direct API)
    llm = OllamaLLM(
        model_name=config.llm.model_name,
        base_url=config.llm.base_url
    )
    
    logger.info(f"LLM initialized: {config.llm.model_name} at {config.llm.base_url}")
    
    # Initialize memory (ChromaDB)
    rag_manager = RAGManager(
        db_path=config.memory.db_path,
        collection_name=config.memory.collection_name
    )
    
    logger.info(f"Memory initialized: ChromaDB at {config.memory.db_path}")
    
    # Initialize orchestrator
    orchestrator = RedAgentOrchestrator(llm, rag_manager)
    orchestrator.compile()
    
    logger.info("Red Agent initialized successfully")
    
    return orchestrator, rag_manager

def run_assessment(target: str, target_type: str = "ip"):
    """
    Run a complete security assessment on a target.
    
    Args:
        target: IP address or URL
        target_type: "ip" or "url"
    """
    
    logger.info(f"\nStarting assessment on target: {target}")
    
    orchestrator, rag_manager = initialize_agent()
    
    # Run the assessment
    final_state = orchestrator.run(
        target=target,
        target_type=target_type,
        target_description=f"Security assessment of {target}"
    )
    
    # Generate report
    report_generator = ReportGenerator()
    report = report_generator.generate_report_dict(final_state)
    
    # Print summary
    summary = report["executive_summary"]
    logger.info(f"\n{'='*60}")
    logger.info("ASSESSMENT RESULTS")
    logger.info(f"{'='*60}")
    logger.info(f"Target: {final_state['target']}")
    logger.info(f"Risk Level: {summary['risk_level']}")
    logger.info(f"Vulnerabilities Found: {summary['vulnerabilities_found']}")
    logger.info(f"  - Critical: {summary['critical_vulnerabilities']}")
    logger.info(f"  - High: {summary['high_vulnerabilities']}")
    logger.info(f"Services Tested: {', '.join(summary['services_tested'])}")
    logger.info(f"{'='*60}\n")
    
    # Store findings in memory for future reference
    for vuln in final_state["vulnerabilities"]:
        rag_manager.store_vulnerability({
            **vuln,
            "target": target
        })
    
    return final_state, report

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="The Red Agent - Autonomous Penetration Testing System")
    parser.add_argument("target", help="Target IP address or URL")
    parser.add_argument("--type", default="ip", choices=["ip", "url"], help="Target type")
    parser.add_argument("--describe", default="", help="Additional description of target")
    
    args = parser.parse_args()
    
    try:
        final_state, report = run_assessment(
            target=args.target,
            target_type=args.type
        )
        
        logger.info("Assessment completed successfully")
        
    except Exception as e:
        logger.error(f"Assessment failed: {e}", exc_info=True)
        sys.exit(1)
