#!/usr/bin/env python3
"""
Red Agent - Fast Assessment Version
Uses shorter prompts and quicker analysis cycles
"""

import sys
import json
import requests
import logging
from datetime import datetime
from pathlib import Path

# Setup logging
log_dir = Path("logs")
log_dir.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / f"assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("RedAgent")

# Ollama Configuration
OLLAMA_API = "http://localhost:11434/api/generate"
MODEL = "llama2"

class FastRedAgent:
    """Fast Penetration Testing Agent"""
    
    def __init__(self, target, target_type="url"):
        self.target = target
        self.target_type = target_type
        self.findings = []
        
    def query_llm(self, prompt: str, temperature=0.5, max_tokens=200):
        """Query Ollama LLM with faster response"""
        logger.debug(f"LLM Query: {prompt[:80]}...")
        
        try:
            # Use faster streaming with early stopping
            response = requests.post(
                OLLAMA_API,
                json={
                    "model": MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "temperature": temperature,
                    "num_predict": max_tokens
                },
                timeout=90
            )
            
            if response.status_code == 200:
                result = response.json().get('response', '').strip()
                return result[:500]  # Limit response length
            else:
                logger.error(f"LLM API error: {response.status_code}")
                return ""
                
        except requests.exceptions.Timeout:
            logger.error("LLM request timed out")
            return ""
        except requests.exceptions.ConnectionError:
            logger.error("Cannot connect to Ollama at http://localhost:11434")
            logger.error("Please run: ollama serve")
            return ""
        except Exception as e:
            logger.error(f"LLM error: {e}")
            return ""
    
    def quick_assessment(self):
        """Fast 3-step assessment"""
        logger.info("="*70)
        logger.info("RED AGENT - QUICK SECURITY ASSESSMENT")
        logger.info("="*70)
        logger.info(f"Target: {self.target}")
        logger.info(f"Type: {self.target_type}")
        logger.info(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info("="*70 + "\n")
        
        # Step 1: Vulnerabilities
        logger.info("STEP 1: Common vulnerabilities for this target")
        vuln_prompt = f"List 3 common vulnerabilities in {self.target_type}s like {self.target.split('/')[2] if '/' in self.target else self.target}. Be brief."
        vulns = self.query_llm(vuln_prompt, temperature=0.3, max_tokens=150)
        if vulns:
            logger.info(f"Vulnerabilities:\n{vulns}\n")
            self.findings.append(("vulnerabilities", vulns))
        
        # Step 2: Exploitation vectors
        logger.info("STEP 2: How to test for vulnerabilities")
        exploit_prompt = f"What are the top 2 ways to test {self.target} for security issues? Brief and actionable."
        exploits = self.query_llm(exploit_prompt, temperature=0.4, max_tokens=150)
        if exploits:
            logger.info(f"Testing approach:\n{exploits}\n")
            self.findings.append(("testing_approach", exploits))
        
        # Step 3: Risk level
        logger.info("STEP 3: Overall risk assessment")
        risk_prompt = f"On a scale of 1-10, what's the typical security risk for {self.target_type}? Brief explanation."
        risk = self.query_llm(risk_prompt, temperature=0.3, max_tokens=100)
        if risk:
            logger.info(f"Risk Level:\n{risk}\n")
            self.findings.append(("risk_level", risk))
        
        # Generate report
        self.save_report()
        
        logger.info("="*70)
        logger.info("ASSESSMENT COMPLETE")
        logger.info(f"Report saved to: logs/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        logger.info("="*70 + "\n")
    
    def save_report(self):
        """Save findings to JSON report"""
        report = {
            "metadata": {
                "target": self.target,
                "target_type": self.target_type,
                "timestamp": datetime.now().isoformat(),
                "assessment_type": "quick_security_analysis"
            },
            "findings": [
                {
                    "category": category,
                    "content": content,
                    "timestamp": datetime.now().isoformat()
                }
                for category, content in self.findings
            ]
        }
        
        report_path = log_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report saved to: {report_path}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python run_fast.py <target> [--type url|ip]")
        print("Examples:")
        print("  python run_fast.py https://example.com")
        print("  python run_fast.py 192.168.1.1 --type ip")
        sys.exit(1)
    
    target = sys.argv[1]
    target_type = "url" if "http" in target else "ip"
    
    if len(sys.argv) > 3 and sys.argv[2] == "--type":
        target_type = sys.argv[3]
    
    agent = FastRedAgent(target=target, target_type=target_type)
    agent.quick_assessment()

if __name__ == "__main__":
    main()
