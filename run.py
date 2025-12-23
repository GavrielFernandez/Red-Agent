#!/usr/bin/env python3
"""
Red Agent - Autonomous Penetration Testing System
Standalone version for URL/IP assessment
"""

import sys
import json
import requests
import logging
from datetime import datetime
from pathlib import Path
import urllib.parse

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

class RedAgent:
    """Autonomous Penetration Testing Agent powered by Llama2"""
    
    def __init__(self, target, target_type="url"):
        self.target = target
        self.target_type = target_type
        self.llm_calls = 0
        self.findings = []
        self.vulnerabilities = []
        
    def query_llm(self, prompt: str, temperature=0.3):
        """Query Ollama LLM"""
        self.llm_calls += 1
        logger.debug(f"LLM Call #{self.llm_calls}: {prompt[:100]}...")
        
        try:
            response = requests.post(
                OLLAMA_API,
                json={
                    "model": MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "temperature": temperature
                },
                timeout=180
            )
            
            if response.status_code == 200:
                result = response.json().get('response', '').strip()
                return result
            else:
                logger.error(f"LLM API error: {response.status_code}")
                return ""
                
        except requests.exceptions.Timeout:
            logger.error("LLM request timed out")
            return ""
        except requests.exceptions.ConnectionError:
            logger.error("Cannot connect to Ollama. Make sure 'ollama serve' is running")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Error querying LLM: {e}")
            return ""
    
    def reconnaissance(self):
        """Phase 1: Information Gathering and Reconnaissance"""
        logger.info("="*70)
        logger.info("PHASE 1: RECONNAISSANCE")
        logger.info("="*70)
        
        prompt = f"""Security assessment of: {self.target}

Brief reconnaissance strategy:
1. Initial information gathering approach
2. Key scanning tools and techniques
3. Most valuable targets to identify
4. Timeline estimate"""
        
        logger.info(f"Target: {self.target}")
        logger.info("Querying LLM for reconnaissance strategy...")
        
        strategy = self.query_llm(prompt)
        if strategy:
            logger.info(f"\nReconnaissance Strategy:\n{strategy}\n")
            self.findings.append({
                "phase": "reconnaissance",
                "type": "strategy",
                "content": strategy,
                "timestamp": datetime.now().isoformat()
            })
            return True
        return False
    
    def vulnerability_analysis(self):
        """Phase 2: Vulnerability Analysis"""
        logger.info("="*70)
        logger.info("PHASE 2: VULNERABILITY ANALYSIS")
        logger.info("="*70)
        
        prompt = f"""Target: {self.target} ({self.target_type})

List top 5 vulnerabilities to look for:
1. Vulnerability name (CVE if known)
2. Severity level
3. How to test
4. Impact if exploited

Keep it brief and actionable."""
        
        logger.info("Analyzing potential vulnerabilities...")
        analysis = self.query_llm(prompt)
        
        if analysis:
            logger.info(f"\nVulnerability Analysis:\n{analysis}\n")
            self.findings.append({
                "phase": "vulnerability_analysis",
                "type": "analysis",
                "content": analysis,
                "timestamp": datetime.now().isoformat()
            })
            return True
        return False
    
    def exploitation_planning(self):
        """Phase 3: Exploitation Planning with Self-Reflection"""
        logger.info("="*70)
        logger.info("PHASE 3: EXPLOITATION PLANNING & SELF-REFLECTION")
        logger.info("="*70)
        
        prompt = f"""Exploitation plan for {self.target}:

1. Top 3 exploitation attempts (ordered by success probability)
2. Tools and techniques needed
3. Expected outcome if successful
4. Fallback strategy
5. Confidence level (0-100)"""
        
        logger.info("Planning exploitation and reflecting on strategy...")
        plan = self.query_llm(prompt)
        
        if plan:
            logger.info(f"\nExploitation Plan & Self-Reflection:\n{plan}\n")
            self.findings.append({
                "phase": "exploitation_planning",
                "type": "plan_and_reflection",
                "content": plan,
                "timestamp": datetime.now().isoformat()
            })
            return True
        return False
    
    def impact_assessment(self):
        """Phase 4: Impact and Risk Assessment"""
        logger.info("="*70)
        logger.info("PHASE 4: IMPACT & RISK ASSESSMENT")
        logger.info("="*70)
        
        prompt = f"""Risk assessment for {self.target}:

1. Overall risk level (Critical/High/Medium/Low)
2. Top 3 business impacts if compromised
3. Quick remediation wins
4. Long-term security improvements needed"""
        
        logger.info("Assessing security impact and risk...")
        assessment = self.query_llm(prompt)
        
        if assessment:
            logger.info(f"\nImpact & Risk Assessment:\n{assessment}\n")
            self.findings.append({
                "phase": "impact_assessment",
                "type": "assessment",
                "content": assessment,
                "timestamp": datetime.now().isoformat()
            })
            return True
        return False
    
    def run_assessment(self):
        """Execute full assessment"""
        logger.info("\n" + "="*70)
        logger.info("RED AGENT - AUTONOMOUS PENETRATION TEST")
        logger.info("="*70)
        logger.info(f"Target: {self.target}")
        logger.info(f"Type: {self.target_type}")
        logger.info(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info("="*70 + "\n")
        
        # Run assessment phases
        self.reconnaissance()
        self.vulnerability_analysis()
        self.exploitation_planning()
        self.impact_assessment()
        
        # Generate report
        self.generate_report()
        
        logger.info("\n" + "="*70)
        logger.info("ASSESSMENT COMPLETE")
        logger.info(f"Total LLM Queries: {self.llm_calls}")
        logger.info(f"Findings: {len(self.findings)}")
        logger.info("="*70 + "\n")
    
    def generate_report(self):
        """Generate assessment report"""
        report = {
            "metadata": {
                "target": self.target,
                "target_type": self.target_type,
                "timestamp": datetime.now().isoformat(),
                "llm_model": MODEL,
                "total_queries": self.llm_calls
            },
            "assessment_phases": self.findings
        }
        
        # Save report to JSON
        report_file = log_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report saved to: {report_file}")
        
        return report

def main():
    if len(sys.argv) < 2:
        print("Usage: python run.py <target> [--type url|ip]")
        print("Examples:")
        print("  python run.py https://tcb.ac.il --type url")
        print("  python run.py 192.168.1.1 --type ip")
        sys.exit(1)
    
    target = sys.argv[1]
    target_type = "url"
    
    # Check for --type flag
    if len(sys.argv) > 3 and sys.argv[2] == "--type":
        target_type = sys.argv[3]
    
    # Create and run agent
    agent = RedAgent(target=target, target_type=target_type)
    agent.run_assessment()

if __name__ == "__main__":
    main()
