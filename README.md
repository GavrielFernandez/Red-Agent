"""
The Red Agent - Autonomous LLM-based Penetration Testing System

PROJECT OVERVIEW
═════════════════════════════════════════════════════════════════════════════

The Red Agent is an autonomous security testing system powered by:
  ✓ LLM reasoning (Llama-3 via Ollama)
  ✓ ReAct framework (Reasoning + Action + Observation)
  ✓ Self-reflection for error recovery
  ✓ Long-term memory (ChromaDB RAG)
  ✓ Integrated penetration testing tools (Nmap, SQLmap, Curl, Hydra)

The agent operates as a cyclic graph that iteratively:
  1. Reasons about the target and decides on next action
  2. Executes the chosen tool
  3. Reflects on results and plans next steps
  4. Repeats until target fully assessed or max iterations reached

QUICK START
═════════════════════════════════════════════════════════════════════════════

1. INSTALL DEPENDENCIES
   $ pip install -r requirements.txt

2. START OLLAMA (Llama-3)
   $ ollama pull llama2  # or llama3 when available
   $ ollama serve

3. START AGENT
   $ python main.py 192.168.1.100 --type ip
   
   OR for Docker target:
   $ python main.py juice.local --type url

PROJECT STRUCTURE
═════════════════════════════════════════════════════════════════════════════

red_agent/
├── config/
│   └── config.py              # All configurable parameters
├── core/
│   ├── state.py               # AgentState TypedDict (complete state schema)
│   ├── nodes_reasoning.py      # Reasoning node (LLM decision making)
│   ├── nodes_execution.py      # Execution node (tool running)
│   ├── nodes_reflection.py     # Reflection node (error analysis & recovery)
│   └── orchestrator.py         # LangGraph orchestrator (main workflow)
├── tools/
│   └── tool_factory.py         # Tool wrappers (Nmap, SQLmap, Curl, Hydra)
├── memory/
│   └── rag.py                  # ChromaDB integration (vector store)
├── prompts/
│   └── system_prompts.py        # LLM system prompts (ReAct format)
├── reporting/
│   └── report_generator.py      # PDF/report generation
├── utils/
│   └── [logger, validators, etc]
├── main.py                      # Entry point
├── IMPLEMENTATION_GUIDE.py      # Complete implementation examples
└── README.md                    # This file


KEY CONCEPTS
═════════════════════════════════════════════════════════════════════════════

1. REACT LOOP (Reasoning + Action + Observation)
   
   Each cycle:
   ┌─────────────────────────────────────────────┐
   │ Thought: "What should I do next?"           │
   │ Action: "nmap"                              │
   │ Action Input: {"target": "192.168.1.100"}   │
   │ Observation: [Tool output]                  │
   │ Reflection: "Did this work? What's next?"   │
   └─────────────────────────────────────────────┘

2. REFLECTION-BASED ERROR RECOVERY
   
   If tool fails:
   ├─ LLM analyzes failure reason
   ├─ Decides: Retry with different params? OR Try different tool?
   ├─ Tracks: What strategies have been tried
   ├─ Prevents: Infinite loops (max 3 retries per tool)
   └─ Result: Adaptive behavior on failures

3. AGENT STATE (AgentState TypedDict)
   
   Holds complete execution context:
   ├─ target: Current target being tested
   ├─ reasoning_history: Chain of thoughts
   ├─ execution_history: All tool runs + results
   ├─ reflections: Analysis of each execution
   ├─ vulnerabilities: Discovered issues
   ├─ retry_strategies: Attempted recovery methods
   ├─ relevant_context: Retrieved from ChromaDB
   └─ [+10 more fields for complete context]

4. MEMORY & LEARNING (ChromaDB RAG)
   
   Agent learns from past assessments:
   ├─ Store: Each vulnerability, exploit result, tool output
   ├─ Retrieve: "Similar vulnerabilities for this service"
   ├─ Reason: "I've seen this before, try approach X"
   └─ Result: Faster, smarter testing over time

ARCHITECTURE DEEP DIVE
═════════════════════════════════════════════════════════════════════════════

[1] REASONING NODE - LLM Decision Making
────────────────────────────────────────
Input:  AgentState + Execution history
Process:
  1. Retrieve relevant context from ChromaDB
  2. Build prompt with:
     - Target information
     - Available tools (strict whitelist)
     - Recent execution history
     - Current plan
     - ReAct format instructions
  3. Call Llama-3 via Ollama
  4. Parse response (Thought/Action/Input)
  5. Validate action is in VALID_TOOLS
  6. Return updated state with parsed action
Output: state with parsed_action + parsed_action_input

Hallucination Prevention:
  ✗ Blocks tools not in whitelist
  ✗ Rejects invalid ReAct format
  ✓ Forces strict format with regex validation
  ✓ Falls back to reflection on parse error

[2] EXECUTION NODE - Tool Running
─────────────────────────────────
Input:  AgentState with parsed_action
Process:
  1. Get tool from ToolFactory (Nmap/SQLmap/Curl/Hydra)
  2. Execute with subprocess + timeout protection
  3. Capture stdout/stderr/return_code
  4. Create ToolExecution record
  5. Add to execution_history
Output: state with execution results

Error Handling:
  ✓ Subprocess timeout → Status=FAILED
  ✓ Tool not found → Status=ERROR
  ✓ Exception caught → Graceful degradation
  ✓ stderr captured for reflection

[3] REFLECTION NODE - Error Analysis & Recovery
────────────────────────────────────────────────
Input:  AgentState with last_execution
Process:
  1. Determine success/failure (return_code + status)
  2. Call LLM to analyze results
  3. Parse LLM reflection (JSON):
     {
       "success": bool,
       "should_retry": bool,
       "confidence": 0.0-1.0,
       "next_action": str
     }
  4. Check retry limits (max 3 per tool)
  5. Make decision:
     ├─ Success → Reset counters, continue
     ├─ Failure + can retry → Adjust params, retry
     └─ Failure + max retries → Log and move forward
  6. Check termination conditions:
     ├─ Loop count >= max_loops?
     ├─ Failed attempts >= threshold?
     └─ Target fully exploited?
Output: Updated state with decision

Key Features:
  ✓ Adaptive retry logic (prevents infinite loops)
  ✓ Strategy tracking (what's been tried)
  ✓ Confidence scoring (how sure are we?)
  ✓ Graceful failure (move forward, not crash)

TOOL INTEGRATIONS
═════════════════════════════════════════════════════════════════════════════

[Nmap] - Network Scanning
  └─ Identifies open ports, services, OS info
  └─ Examples:
      • nmap -sS -p 1-10000 -sV target  (SYN scan)
      • nmap -A -T4 target              (Aggressive)
      • nmap -sU target                 (UDP scan)

[SQLmap] - SQL Injection Testing
  └─ Tests and exploits SQL injection vulnerabilities
  └─ Examples:
      • sqlmap -u "http://target/page.php?id=1" --dbs
      • sqlmap -u "target" -d "username=admin&password=test" --dbs
      • sqlmap -u "target" --tables -D database_name

[Curl] - HTTP/HTTPS Requests
  └─ Manual HTTP testing, API probing, credential testing
  └─ Examples:
      • curl -X POST -d "data" -H "Header: value" target
      • curl -u username:password http://target
      • curl -L -v http://target  (Follow redirects, verbose)

[Hydra] - Credential Brute-forcing
  └─ Tests weak authentication
  └─ Examples:
      • hydra -l admin -P wordlist.txt http://target http-post-form
      • hydra -l admin -p password target ssh
      • hydra -L users.txt -P passwords.txt target ftp

SYSTEM PROMPT STRATEGY
═════════════════════════════════════════════════════════════════════════════

Core Principle: Enforce ReAct format, prevent hallucination

PROMPT STRUCTURE:
  1. [ROLE] "You are The Red Agent, autonomous penetration tester"
  2. [TARGET] "Target: 192.168.1.100 (IP)"
  3. [TOOLS] "AVAILABLE TOOLS: nmap, sqlmap, curl, hydra"
  4. [FORMAT] "MANDATORY FORMAT: Thought/Action/Action Input"
  5. [CONTEXT] "Execution history, current plan, findings"
  6. [TASK] "Decide next action. Use ReAct format (must repeat rules)"

Why this works:
  ✓ Whitelist before any inference
  ✓ Format rules repeated (binding)
  ✓ History grounds reasoning
  ✓ Explicit task at end
  ✓ No room for creativity/hallucination

REFLECTION PROMPT:
  Input: Last execution (tool, status, output)
  Output: JSON with:
    - "success": Was this execution successful?
    - "analysis": What did we learn?
    - "should_retry": Try again with different params?
    - "confidence": How certain are we? (0.0-1.0)

Example:
  Tool: sqlmap
  Status: TIMEOUT
  Output: "Command timed out after 600s"
  
  LLM Returns:
  {
    "success": false,
    "analysis": "SQLmap is too slow with --risk 3",
    "should_retry": true,
    "next_action": "reduce risk to 1",
    "confidence": 0.75
  }

EXAMPLE WORKFLOWS
═════════════════════════════════════════════════════════════════════════════

SCENARIO 1: Successful Attack Path Discovery
─────────────────────────────────────────────
Target: 192.168.1.100 (OWASP Juice Shop)

Cycle 1: Nmap scan (open ports 80, 443, 3000)
Cycle 2: Curl to 3000/api/login (test SQL injection)
Cycle 3: SQLmap confirmation (SQL injection confirmed)
Cycle 4: Extract databases
Cycle 5: Hydra brute-force default credentials
Cycle 6: Analyze findings + generate report

Result: 8 vulnerabilities found, 3 exploited

SCENARIO 2: Tool Failure with Recovery
─────────────────────────────────────────
Cycle 1: Nmap scan → SUCCESS
Cycle 2: SQLmap scan → TIMEOUT (fails)
Cycle 2.1: Reflection → "Risk level too high, retry with risk=1"
Cycle 2.2: SQLmap retry → SUCCESS (with lower risk)
Cycle 3: Continue testing

Result: Agent adapted to timeout, recovered gracefully

SCENARIO 3: Hallucination Prevention
──────────────────────────────────────
LLM tries: Action: "bash"
Validation: "bash" NOT in VALID_TOOLS
Response: ERROR - tool not found
Recovery: Reflection forces valid action choice
Result: Agent cannot escape tool whitelist

CONFIGURATION
═════════════════════════════════════════════════════════════════════════════

Modify config/config.py for your setup:

LLMConfig:
  - model_name: Change to "llama3" when available
  - temperature: 0.3 (low = consistent), 0.9 (high = creative)
  - max_tokens: Increase for complex reasoning

ToolConfig:
  - Timeouts: Adjust based on target responsiveness
  - max_retries: 3 (increase for flaky targets)

MemoryConfig:
  - k_relevant_docs: 5 (more = slower but better context)
  - db_path: Point to your ChromaDB storage

AgentConfig:
  - max_reasoning_steps: 15 (increase for complex targets)
  - max_reflection_loops: 3 (failure threshold)
  - reflection_threshold: 0.6 (confidence cutoff)

RUNNING THE AGENT
═════════════════════════════════════════════════════════════════════════════

# Basic usage
$ python main.py 192.168.1.100 --type ip

# With description
$ python main.py 192.168.1.100 --type ip --describe "OWASP Juice Shop"

# Test URL
$ python main.py http://target.local:3000 --type url

# Output files
└─ logs/red_agent.log          # Execution log
└─ chroma_db/                  # Memory database
└─ report.json                 # JSON report

EXTENDING THE AGENT
═════════════════════════════════════════════════════════════════════════════

Adding a new tool:

1. Create tool in tools/tool_factory.py
   
   class MyNewTool(BaseTool):
       def execute(self, params):
           # Run your tool
           return {"stdout": "...", "return_code": 0}

2. Register in ToolFactory
   
   self.tools["my_tool"] = MyNewTool()

3. Add to ReasoningNode.VALID_TOOLS
   
   VALID_TOOLS = {
       "nmap": "...",
       "my_tool": "Description of my tool"
   }

4. Test with a prompt mentioning the tool

DEBUGGING
═════════════════════════════════════════════════════════════════════════════

Enable detailed logging:
  config.agent.enable_detailed_logging = True

Check execution history:
  print(state['execution_history'])
  # See all tool runs with outputs

Check reflections:
  print(state['reflections'])
  # See LLM analysis of each execution

Check vulnerabilities:
  print(state['vulnerabilities'])
  # See all discovered findings

Check ChromaDB:
  rag_manager.get_statistics()
  # See what's stored in memory

SECURITY NOTES
═════════════════════════════════════════════════════════════════════════════

⚠️  CRITICAL: This agent executes external tools
   - Only run against authorized targets
   - Ensure proper network isolation
   - Monitor resource usage (CPU, disk, network)

✓ Built-in protections:
   - Tool whitelist (no arbitrary commands)
   - Timeout enforcement (max execution time)
   - Output capture (no stderr flooding)
   - Reflection limits (prevent infinite loops)

✓ Security best practices:
   - Use in isolated Docker environment
   - Restrict network access (firewall rules)
   - Monitor agent behavior (logging)
   - Run only against your own systems

PERFORMANCE TIPS
═════════════════════════════════════════════════════════════════════════════

Faster testing:
  - Reduce max_reasoning_steps (e.g., 10 instead of 15)
  - Reduce nmap port range (e.g., 1-1000)
  - Increase temperature (0.5 for faster, less accurate)

Better accuracy:
  - Increase max_reasoning_steps
  - Lower temperature (0.1-0.3 for consistency)
  - Increase reflection_threshold (be more picky)
  - Store more findings in ChromaDB

Handle slow targets:
  - Increase tool timeouts
  - Reduce risk levels in SQLmap
  - Increase max_retries
  - Use curl with --connect-timeout

TROUBLESHOOTING
═════════════════════════════════════════════════════════════════════════════

"Connection refused on Ollama"
  → Check: Is `ollama serve` running?
  → Check: Is it listening on http://localhost:11434?

"Tool not found: nmap"
  → Install: sudo apt-get install nmap
  → Check PATH: which nmap

"Agent loops infinitely"
  → Increase max_reflection_loops threshold
  → Decrease max_reasoning_steps
  → Check target is actually accessible

"ChromaDB connection error"
  → Check: chroma_db/ directory permissions
  → Try: python -c "from chromadb import Client; Client()"

NEXT STEPS
═════════════════════════════════════════════════════════════════════════════

1. Read IMPLEMENTATION_GUIDE.py for detailed examples
2. Test with OWASP Juice Shop in Docker
3. Customize prompts in prompts/system_prompts.py
4. Add new tools following the BaseTool pattern
5. Integrate with your own vulnerability database

Author: Lead Developer
Version: 1.0.0
License: Proprietary (Security Research)
"""

if __name__ == "__main__":
    import sys
    print(__doc__)
    sys.exit(0)
