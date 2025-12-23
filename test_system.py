#!/usr/bin/env python3
"""
Simple test to verify Red Agent system is ready
Tests basic functionality without full dependency chain
"""

import sys
import json
from datetime import datetime

print("\n" + "="*60)
print("RED AGENT - System Status Check")
print("="*60 + "\n")

# Test 1: Python version
python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
print(f"✓ Python Version: {python_version}")

# Test 2: Check core files exist
import os
core_files = [
    'config/config.py',
    'core/state.py', 
    'core/nodes_reasoning.py',
    'core/nodes_execution.py',
    'core/nodes_reflection.py',
    'core/orchestrator.py',
    'memory/rag.py',
    'tools/tool_factory.py',
    'prompts/system_prompts.py',
    'reporting/report_generator.py',
    'main.py'
]

print(f"\nCore Files ({len(core_files)} required):")
all_present = True
for file in core_files:
    exists = os.path.exists(file)
    status = "✓" if exists else "✗"
    print(f"  {status} {file}")
    if not exists:
        all_present = False

# Test 3: Check dependencies
print(f"\nPython Packages:")
packages = ['langchain', 'langgraph', 'chromadb', 'pydantic', 'ollama', 'reportlab']
all_installed = True

for pkg in packages:
    try:
        __import__(pkg)
        print(f"  ✓ {pkg}")
    except ImportError:
        print(f"  ✗ {pkg} (MISSING)")
        all_installed = False

# Summary
print("\n" + "-"*60)
if all_present and all_installed:
    print("STATUS: ✓ READY - All components present")
    print("\nNext steps:")
    print("1. Install Ollama from https://ollama.ai")
    print("2. Run: ollama pull llama2")
    print("3. Run: ollama serve (in separate terminal)")
    print("4. Run: python main.py 192.168.1.1 --type ip")
else:
    print("STATUS: ✗ INCOMPLETE - Some components missing")
    if not all_present:
        print("  - Missing core files")
    if not all_installed:
        print("  - Missing Python packages (run: pip install -r requirements.txt)")

print("="*60 + "\n")
