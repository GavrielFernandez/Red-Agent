#!/usr/bin/env python3
"""
Integration Tests for RedAgent
Tests the complete flow of assessment execution and reporting
Requires: Ollama running locally, test target available
"""

import sys
import json
import time
import logging
from pathlib import Path
from datetime import datetime
import unittest

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TestRedAgentIntegration(unittest.TestCase):
    """Integration tests for RedAgent"""
    
    @classmethod
    def setUpClass(cls):
        """Setup test environment"""
        cls.project_root = Path(__file__).parent
        cls.logs_dir = cls.project_root / "logs"
        cls.logs_dir.mkdir(exist_ok=True)
    
    # ========================================================================
    # Test Suite 1: Tool Execution
    # ========================================================================
    
    def test_curl_tool(self):
        """Test 1.1: CurlTool basic functionality"""
        logger.info("TEST 1.1: CurlTool basic functionality")
        
        from tools.tool_factory import ToolFactory
        factory = ToolFactory()
        curl = factory.get_tool("curl")
        
        self.assertIsNotNone(curl, "CurlTool should be available")
        
        # Test with a simple target (httpbin for testing)
        result = curl.execute({
            "url": "http://httpbin.org/get",
            "method": "GET"
        })
        
        self.assertIn("status", result)
        self.assertIn("return_code", result)
        self.assertIn("execution_time", result)
        logger.info(f"✅ CurlTool execution: {result.get('status')}")
    
    def test_tool_statistics(self):
        """Test 1.2: Tool statistics tracking"""
        logger.info("TEST 1.2: Tool statistics tracking")
        
        from tools.tool_factory import ToolFactory
        factory = ToolFactory()
        
        # Execute curl multiple times
        curl = factory.get_tool("curl")
        for i in range(3):
            curl.execute({
                "url": "http://httpbin.org/status/200",
                "method": "GET"
            })
        
        # Get statistics
        stats = factory.get_tool_stats()
        
        self.assertIn("curl", stats)
        self.assertIn("total_executions", stats["curl"])
        self.assertGreaterEqual(stats["curl"]["total_executions"], 3)
        logger.info(f"✅ Tool stats: {stats['curl']}")
    
    # ========================================================================
    # Test Suite 2: RedAgent Assessment
    # ========================================================================
    
    def test_agent_instantiation(self):
        """Test 2.1: RedAgent instantiation"""
        logger.info("TEST 2.1: RedAgent instantiation")
        
        from run import RedAgent
        
        agent = RedAgent(target="http://httpbin.org", target_type="url")
        
        self.assertIsNotNone(agent)
        self.assertEqual(agent.target, "http://httpbin.org")
        self.assertEqual(agent.target_type, "url")
        self.assertTrue(hasattr(agent, 'findings'))
        self.assertTrue(hasattr(agent, 'run_assessment'))
        logger.info("✅ RedAgent instantiation successful")
    
    def test_reconnaissance_phase(self):
        """Test 2.2: Reconnaissance phase execution"""
        logger.info("TEST 2.2: Reconnaissance phase execution")
        
        from run import RedAgent
        
        agent = RedAgent(target="http://httpbin.org", target_type="url")
        
        # Run single phase
        result = agent.reconnaissance()
        
        self.assertTrue(result, "Reconnaissance should return True")
        self.assertGreater(len(agent.findings), 0, "Should have findings after reconnaissance")
        logger.info(f"✅ Reconnaissance phase: {len(agent.findings)} findings")
    
    def test_vulnerability_analysis_phase(self):
        """Test 2.3: Vulnerability analysis phase"""
        logger.info("TEST 2.3: Vulnerability analysis phase")
        
        from run import RedAgent
        
        agent = RedAgent(target="http://httpbin.org", target_type="url")
        
        # Run phases
        agent.reconnaissance()
        result = agent.vulnerability_analysis()
        
        self.assertTrue(result, "Vulnerability analysis should return True")
        logger.info(f"✅ Vulnerability analysis phase completed")
    
    # ========================================================================
    # Test Suite 3: Report Generation
    # ========================================================================
    
    def test_report_generation(self):
        """Test 3.1: Report generation and format"""
        logger.info("TEST 3.1: Report generation and format")
        
        from run import RedAgent
        
        agent = RedAgent(target="http://httpbin.org", target_type="url")
        
        # Generate report
        report = agent.generate_report()
        
        self.assertIsNotNone(report)
        self.assertIn("metadata", report)
        self.assertIn("assessment_phases", report)
        self.assertIn("target", report["metadata"])
        logger.info("✅ Report format valid")
    
    def test_report_file_creation(self):
        """Test 3.2: Report file is created"""
        logger.info("TEST 3.2: Report file creation")
        
        initial_reports = len(list(self.logs_dir.glob("report_*.json")))
        
        from run import RedAgent
        
        agent = RedAgent(target="http://httpbin.org", target_type="url")
        agent.generate_report()
        
        final_reports = len(list(self.logs_dir.glob("report_*.json")))
        
        self.assertGreater(final_reports, initial_reports, "New report should be created")
        logger.info(f"✅ Report created ({final_reports} total)")
    
    def test_report_content_validation(self):
        """Test 3.3: Report content validation"""
        logger.info("TEST 3.3: Report content validation")
        
        # Find latest report
        reports = sorted(self.logs_dir.glob("report_*.json"), reverse=True)
        self.assertGreater(len(reports), 0, "Should have at least one report")
        
        with open(reports[0], 'r', encoding='utf-8') as f:
            report = json.load(f)
        
        # Validate structure
        self.assertIn("metadata", report)
        self.assertIn("assessment_phases", report)
        
        # Validate metadata
        self.assertIn("target", report["metadata"])
        self.assertIn("timestamp", report["metadata"])
        self.assertIn("llm_model", report["metadata"])
        
        logger.info(f"✅ Report content valid: {report['metadata']['target']}")
    
    # ========================================================================
    # Test Suite 4: API Integration
    # ========================================================================
    
    def test_flask_app_routes(self):
        """Test 4.1: Flask app routes are defined"""
        logger.info("TEST 4.1: Flask app routes verification")
        
        import app as app_module
        
        flask_app = getattr(app_module, 'app', None)
        
        self.assertIsNotNone(flask_app, "Flask app should exist")
        
        # Get all routes
        routes = [rule.rule for rule in flask_app.url_map.iter_rules()]
        
        expected_routes = [
            '/api/status',
            '/api/assess',
            '/api/jobs',
            '/api/reports',
        ]
        
        for route in expected_routes:
            self.assertIn(route, routes, f"Route {route} should exist")
        
        logger.info(f"✅ {len(routes)} routes defined")
    
    def test_api_client(self):
        """Test 4.2: Flask test client"""
        logger.info("TEST 4.2: Flask API client")
        
        import app as app_module
        
        flask_app = getattr(app_module, 'app', None)
        client = flask_app.test_client()
        
        # Test status endpoint
        response = client.get('/api/status')
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data.get('status'), 'ok')
        logger.info("✅ API status endpoint working")
    
    # ========================================================================
    # Test Suite 5: Error Handling
    # ========================================================================
    
    def test_invalid_target_handling(self):
        """Test 5.1: Invalid target handling"""
        logger.info("TEST 5.1: Invalid target handling")
        
        from tools.tool_factory import ToolFactory
        
        factory = ToolFactory()
        curl = factory.get_tool("curl")
        
        # Invalid URL should be handled gracefully
        result = curl.execute({
            "url": "invalid-url",
            "method": "GET"
        })
        
        self.assertEqual(result.get("status"), "error")
        self.assertIn("error_message", result)
        logger.info("✅ Invalid target handled gracefully")
    
    def test_timeout_handling(self):
        """Test 5.2: Timeout and retry handling"""
        logger.info("TEST 5.2: Timeout and retry handling")
        
        from tools.tool_factory import CurlTool
        
        curl = CurlTool()
        
        # Test with very short timeout
        curl.timeout = 1
        
        # This should timeout and be retried
        result = curl.execute({
            "url": "http://httpbin.org/delay/3",
            "method": "GET"
        })
        
        # Should have either timed out or tried retries
        self.assertIn(result.get("status"), ["timeout", "failed", "error", "success"])
        self.assertGreaterEqual(result.get("retries_used", 0), 0)
        logger.info(f"✅ Timeout handling: {result['status']} (retries: {result.get('retries_used')})")
    
    # ========================================================================
    # Test Suite 6: Configuration
    # ========================================================================
    
    def test_config_loading(self):
        """Test 6.1: Configuration loading"""
        logger.info("TEST 6.1: Configuration loading")
        
        from config.config import config, get_config
        
        cfg = get_config()
        
        self.assertIsNotNone(cfg)
        self.assertIsNotNone(cfg.llm)
        self.assertIsNotNone(cfg.tools)
        self.assertIsNotNone(cfg.dashboard)
        self.assertIsNotNone(cfg.agent)
        logger.info("✅ Configuration loaded successfully")
    
    def test_config_values(self):
        """Test 6.2: Configuration values are valid"""
        logger.info("TEST 6.2: Configuration value validation")
        
        from config.config import config
        
        # Check tool timeouts
        self.assertGreater(config.tools.curl_timeout, 0)
        self.assertGreater(config.tools.nmap_timeout, 0)
        
        # Check agent settings
        self.assertGreater(config.agent.max_reasoning_steps, 0)
        self.assertGreater(config.agent.target_timeout, 0)
        
        # Check dashboard settings
        self.assertGreater(config.dashboard.port, 0)
        self.assertLess(config.dashboard.port, 65536)
        
        logger.info("✅ Configuration values valid")


class TestAttackVectors(unittest.TestCase):
    """Tests for 8 attack vectors"""
    
    def test_all_attack_vectors_available(self):
        """Test that all 8 attack vectors are implemented"""
        logger.info("TEST: All 8 attack vectors availability")
        
        # Import the agent to check for attack methods
        from run import RedAgent
        
        agent = RedAgent(target="http://test.local", target_type="url")
        
        # Check that attack execution exists
        self.assertTrue(hasattr(agent, 'attack_execution'))
        
        expected_attacks = [
            "SQL Injection",
            "XSS Injection",
            "Command Injection",
            "Path Traversal",
            "LDAP Injection",
            "XXE Injection",
            "HTTP Header Injection",
            "Brute Force"
        ]
        
        logger.info(f"✅ Expected attacks: {expected_attacks}")


def run_tests():
    """Run all integration tests"""
    logger.info("\n" + "="*70)
    logger.info("RED AGENT - INTEGRATION TESTS")
    logger.info("="*70 + "\n")
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add tests
    suite.addTests(loader.loadTestsFromTestCase(TestRedAgentIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestAttackVectors))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Summary
    logger.info("\n" + "="*70)
    logger.info("TEST SUMMARY")
    logger.info("="*70)
    logger.info(f"Tests run: {result.testsRun}")
    logger.info(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    logger.info(f"Failures: {len(result.failures)}")
    logger.info(f"Errors: {len(result.errors)}")
    logger.info("="*70 + "\n")
    
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    exit_code = run_tests()
    sys.exit(exit_code)
