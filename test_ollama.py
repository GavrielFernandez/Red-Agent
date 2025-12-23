#!/usr/bin/env python3
"""
Test Red Agent with direct Ollama integration
Simple version to avoid langchain_community import issues
"""

import sys
import json
import logging
from datetime import datetime
import requests

print("\n" + "="*70)
print("RED AGENT - TESTING WITH OLLAMA")
print("="*70 + "\n")

# Test 1: Check if Ollama is running
print("Step 1: Checking if Ollama is running...")
try:
    response = requests.get("http://localhost:11434/api/tags", timeout=5)
    if response.status_code == 200:
        models = response.json()
        print(f"✓ Ollama is running")
        print(f"✓ Available models: {[m['name'] for m in models.get('models', [])]}")
    else:
        print(f"✗ Ollama is not responding correctly (status: {response.status_code})")
        sys.exit(1)
except requests.exceptions.ConnectionError:
    print("✗ Cannot connect to Ollama at http://localhost:11434")
    print("  Make sure: ollama serve is running in another terminal")
    sys.exit(1)
except Exception as e:
    print(f"✗ Error: {e}")
    sys.exit(1)

# Test 2: Test LLM with a simple prompt
print("\nStep 2: Testing Llama2 LLM...")
try:
    test_prompt = "What is a penetration test? Answer in one sentence."
    
    response = requests.post(
        "http://localhost:11434/api/generate",
        json={
            "model": "llama2",
            "prompt": test_prompt,
            "stream": False,
            "temperature": 0.3
        },
        timeout=60
    )
    
    if response.status_code == 200:
        result = response.json()
        llm_response = result.get('response', '').strip()
        print(f"✓ LLM responded successfully")
        print(f"  Response: {llm_response[:100]}...")
    else:
        print(f"✗ LLM request failed: {response.status_code}")
        sys.exit(1)
        
except requests.exceptions.Timeout:
    print("✗ Timeout waiting for LLM response")
    sys.exit(1)
except Exception as e:
    print(f"✗ Error testing LLM: {e}")
    sys.exit(1)

# Test 3: Check Red Agent components
print("\nStep 3: Checking Red Agent components...")
try:
    # Test config
    from config.config import config
    print(f"✓ Config loaded")
    
    # Test state
    from core.state import AgentState, create_initial_state
    print(f"✓ AgentState module loaded")
    
    # Test memory
    from memory.rag import RAGManager
    print(f"✓ Memory/RAG module loaded")
    
    # Test tools
    from tools.tool_factory import ToolFactory
    print(f"✓ Tool Factory loaded")
    
except Exception as e:
    print(f"✗ Error loading components: {e}")
    sys.exit(1)

# Summary
print("\n" + "="*70)
print("✓ ALL TESTS PASSED - RED AGENT IS READY!")
print("="*70)
print("\nYou can now run:")
print("  python main.py 192.168.1.1 --type ip")
print("  python main.py http://example.com --type url")
print("\nOllama is running and ready to power the autonomous agent.")
print("="*70 + "\n")
