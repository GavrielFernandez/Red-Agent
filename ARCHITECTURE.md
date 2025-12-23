"""
THE RED AGENT - COMPLETE ARCHITECTURE DOCUMENT

A comprehensive guide to the autonomous LLM-based penetration testing system.
This document provides all necessary information for understanding, maintaining,
and extending the system.

═══════════════════════════════════════════════════════════════════════════════
PART 1: SYSTEM OVERVIEW
═══════════════════════════════════════════════════════════════════════════════

PROJECT GOAL:
  Create a fully autonomous agent that receives a target (IP/URL), scans it,
  identifies vulnerabilities, exploits them, and generates a comprehensive
  penetration testing report.

CORE INNOVATION:
  ReAct Loop + Self-Reflection + LLM-driven decision making + Long-term memory
  
  Result: An agent that:
    ✓ Reasons about the target systematically
    ✓ Takes actions (tool execution)
    ✓ Observes results and learns
    ✓ Reflects on failures and adapts
    ✓ Remembers past findings for context
    ✓ Cannot hallucinate non-existent tools

═══════════════════════════════════════════════════════════════════════════════
PART 2: ARCHITECTURE DIAGRAM
═══════════════════════════════════════════════════════════════════════════════

INPUT: Target (IP/URL)
  │
  ├─────────────────────────────────────────────────────┐
  │                                                     │
  ▼                                                     │
┌─────────────────────────────────────────────────────┐ │
│         LANGGRAPH ORCHESTRATOR (Main Graph)         │ │
│                                                     │ │
│  ┌─────────────────────────────────────────────┐   │ │
│  │ Entry Point: Initialize AgentState          │   │ │
│  │ - target, empty history, max_loops=15       │   │ │
│  └────────────┬────────────────────────────────┘   │ │
│               │                                     │ │
│               ▼                                     │ │
│  ┌─────────────────────────────────────────────┐   │ │
│  │    [REASONING NODE]                         │   │ │
│  │  ┌─────────────────────────────────────┐    │   │ │
│  │  │ 1. Retrieve context from ChromaDB   │    │   │ │
│  │  │ 2. Build prompt with:               │    │   │ │
│  │  │    - Target info                    │    │   │ │
│  │  │    - Execution history              │    │   │ │
│  │  │    - Available tools (WHITELIST)    │    │   │ │
│  │  │    - ReAct format instructions      │    │   │ │
│  │  │ 3. Call Ollama Llama-3              │    │   │ │
│  │  │ 4. Parse response (Thought/Action)  │    │   │ │
│  │  │ 5. Validate action in VALID_TOOLS   │    │   │ │
│  │  │ 6. Return: parsed_action +          │    │   │ │
│  │  │           parsed_action_input       │    │   │ │
│  │  └─────────────────────────────────────┘    │   │ │
│  └────────────┬────────────────────────────────┘   │ │
│               │                                     │ │
│               ▼                                     │ │
│  ┌─────────────────────────────────────────────┐   │ │
│  │    [EXECUTION NODE]                         │   │ │
│  │  ┌─────────────────────────────────────┐    │   │ │
│  │  │ 1. Get tool from ToolFactory         │    │   │ │
│  │  │ 2. Execute subprocess with timeout  │    │   │ │
│  │  │ 3. Capture stdout/stderr/return_code│    │   │ │
│  │  │ 4. Create ToolExecution record      │    │   │ │
│  │  │ 5. Add to execution_history         │    │   │ │
│  │  │ 6. Return: state with results       │    │   │ │
│  │  └─────────────────────────────────────┘    │   │ │
│  └────────────┬────────────────────────────────┘   │ │
│               │                                     │ │
│               ▼                                     │ │
│  ┌─────────────────────────────────────────────┐   │ │
│  │    [REFLECTION NODE]                        │   │ │
│  │  ┌─────────────────────────────────────┐    │   │ │
│  │  │ 1. Analyze last execution           │    │   │ │
│  │  │ 2. Call LLM for analysis            │    │   │ │
│  │  │ 3. Parse reflection (JSON)          │    │   │ │
│  │  │    - success: bool                  │    │   │ │
│  │  │    - should_retry: bool             │    │   │ │
│  │  │    - confidence: float              │    │   │ │
│  │  │ 4. Check retry limits               │    │   │ │
│  │  │ 5. Make decision:                   │    │   │ │
│  │  │    Success → Reset, continue        │    │   │ │
│  │  │    Fail + retry ok → Retry          │    │   │ │
│  │  │    Fail + max retries → Move on     │    │   │ │
│  │  │ 6. Check termination conditions     │    │   │ │
│  │  └─────────────────────────────────────┘    │   │ │
│  └────────────┬────────────────────────────────┘   │ │
│               │                                     │ │
│               ▼                                     │ │
│         ┌─────────────────┐                       │ │
│         │ Should Continue?│                       │ │
│         └────┬────────┬───┘                       │ │
│              │ Yes    │ No                        │ │
│              ▼        ▼                           │ │
│           Loop     [END NODE]                     │ │
│            ▲           │                          │ │
│            │           │                          │ │
│            └─→ Back to REASONING                 │ │
│                (loop_count++) ─────┐             │ │
│                                    │             │ │
└────────────────────────────────────┼─────────────┘ │
                                     │               │
OUTPUT: Final AgentState             │               │
  - vulnerabilities[]                │               │
  - execution_history[]              │               │
  - reflections[]                    │               │
  - termination_reason               │               │
  └──────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════════
PART 3: AGENT STATE - Complete Data Model
═══════════════════════════════════════════════════════════════════════════════

AgentState (TypedDict) - Holds ALL execution context

TARGET & IDENTIFICATION:
  ├─ target: str                          # "192.168.1.100" or "target.com"
  ├─ target_type: str                     # "ip" or "url"
  └─ target_description: str              # "OWASP Juice Shop"

REASONING & PLANNING:
  ├─ reasoning_history: List[str]         # ["Thought 1", "Thought 2", ...]
  ├─ current_plan: str                    # "Attack strategy overview"
  ├─ plan_steps: List[str]                # ["Step 1", "Step 2", ...]
  └─ current_step_index: int              # Which step we're on

EXECUTION TRACKING:
  ├─ execution_history: List[ToolExecution] # Complete log of all tool runs
  ├─ last_execution: Optional[ToolExecution] # Most recent execution
  ├─ failed_attempts: int                  # Consecutive failures count
  └─ total_executions: int                 # Total tools run so far

REFLECTION & LEARNING:
  ├─ reflections: List[ReflectionEntry]   # Analysis of each execution
  ├─ last_reflection: Optional[ReflectionEntry]
  ├─ retry_strategies: Dict[str, List[str]] # Attempted recovery methods
  │  └─ Format: {tool_name: [strategy1, strategy2, ...]}
  └─ [Tracks what strategies have been tried to prevent loops]

DISCOVERIES:
  ├─ vulnerabilities: List[VulnerabilityFinding] # Found issues
  ├─ exploited_services: List[str]               # Successfully compromised
  ├─ scanned_ports: Dict[str, str]               # port -> service mapping
  └─ open_services: List[Dict]                   # Detailed service info

CONTEXT & MEMORY:
  └─ relevant_context: List[str]          # Retrieved from ChromaDB

CONTROL FLOW:
  ├─ loop_count: int                      # Cycles completed
  ├─ max_loops: int                       # Maximum allowed cycles
  ├─ should_continue: bool                # Continue to next cycle?
  └─ termination_reason: Optional[str]    # Why did we stop?

LLM INTERACTION:
  ├─ last_llm_response: Optional[str]     # Raw LLM output
  ├─ parsed_action: Optional[str]         # Extracted action
  └─ parsed_action_input: Optional[Dict]  # Tool arguments

ERROR TRACKING:
  ├─ errors: List[Dict]                   # [{type, message, timestamp}]
  └─ warnings: List[Dict]                 # [{level, message, timestamp}]

REPORTING:
  ├─ report_data: Dict[str, Any]          # Compiled report
  └─ summary: str                         # Executive summary

═══════════════════════════════════════════════════════════════════════════════
PART 4: THE THREE CORE NODES
═══════════════════════════════════════════════════════════════════════════════

[1] REASONING NODE: nodes_reasoning.py
─────────────────────────────────────────

PURPOSE: Decide what action to take next

INPUT: AgentState with full context

PROCESS:
  1. Retrieve relevant documents from ChromaDB
     → "SQL injection vulnerabilities for port 3000"
     → Returns up to k=5 similar findings
  
  2. Build Llama-3 prompt:
     ┌────────────────────────────────────┐
     │ System: "You are The Red Agent"    │
     │ Target: 192.168.1.100              │
     │ Available Tools:                   │
     │  - nmap: Network scanning          │
     │  - sqlmap: SQL injection testing   │
     │  - curl: HTTP requests             │
     │  - hydra: Brute-forcing            │
     │ Recent History:                    │
     │  1. nmap: SUCCESS                  │
     │  2. curl: FAILED (timeout)         │
     │ Current Plan:                      │
     │  Step 1: ✓ Scan ports              │
     │  Step 2: ○ Test SQL injection      │
     │ MANDATORY FORMAT:                  │
     │  Thought: <reasoning>              │
     │  Action: <tool_name>               │
     │  Action Input: <json>              │
     │ Your task: Decide next action      │
     └────────────────────────────────────┘
  
  3. Call Llama-3 via Ollama
     → model: "llama2" (8B parameter)
     → temperature: 0.3 (consistency)
     → max_tokens: 2048
  
  4. Parse response using regex:
     ├─ Extract "Thought: ..."
     ├─ Extract "Action: ..."
     ├─ Extract "Action Input: ..."
     └─ Handle JSON parsing for input
  
  5. Validate action:
     ├─ Is it in VALID_TOOLS?
     ├─ If YES → Continue to execution
     └─ If NO → Error + retry reasoning

OUTPUT: Updated state with:
  ├─ parsed_action: "sqlmap"
  ├─ parsed_action_input: {"url": "http://target:3000/api", "dbs": true}
  ├─ reasoning_history: [..., new thought]
  └─ last_llm_response: raw output

HALLUCINATION PREVENTION:
  ✓ Tool whitelist checked BEFORE inference
  ✓ ReAct format enforced with regex
  ✓ Invalid actions → ERROR, not hallucination
  ✓ Format violations → Parse error recovery


[2] EXECUTION NODE: nodes_execution.py
──────────────────────────────────────

PURPOSE: Execute the decided tool

INPUT: AgentState with parsed_action

PROCESS:
  1. Retrieve tool from ToolFactory
     ├─ nmap → NmapTool instance
     ├─ sqlmap → SqlmapTool instance
     ├─ curl → CurlTool instance
     └─ hydra → HydraTool instance
  
  2. Execute tool with safety features:
     ├─ Subprocess isolation (no shell interpretation)
     ├─ Timeout protection (e.g., 300s for nmap)
     ├─ stdout/stderr capture
     └─ Return code tracking
  
  3. Handle execution outcomes:
     ├─ SUCCESS (return_code=0) → Status=SUCCESS
     ├─ FAILED (return_code!=0) → Status=FAILED
     ├─ TIMEOUT (>timeout_secs) → Status=FAILED, stderr="TIMEOUT"
     └─ EXCEPTION → Status=ERROR, stderr=exception_message
  
  4. Create ToolExecution record:
     {
         "tool_name": "sqlmap",
         "tool_args": {"url": "...", "dbs": true},
         "stdout": "[+] Found database: users",
         "stderr": "",
         "return_code": 0,
         "execution_time": 42.3,
         "status": "success",
         "retry_count": 0,
         "timestamp": 1234567890.0
     }
  
  5. Update state:
     ├─ Add to execution_history
     ├─ Set last_execution
     ├─ Increment total_executions
     ├─ Update failed_attempts counter

OUTPUT: Updated state with:
  ├─ execution_history: [..., new execution]
  ├─ last_execution: complete tool run record
  ├─ failed_attempts: 0 if success, +1 if failed
  └─ total_executions: incremented


[3] REFLECTION NODE: nodes_reflection.py
─────────────────────────────────────────

PURPOSE: Analyze execution results and decide on next steps

INPUT: AgentState with last_execution

PROCESS:
  1. Determine success/failure:
     ├─ return_code == 0? → SUCCESS
     ├─ status in [SUCCESS, PARTIAL]? → SUCCESS
     ├─ status in [FAILED, ERROR]? → FAILURE
     └─ Use both criteria for robust decision

  2. Generate reflection prompt:
     ┌──────────────────────────────┐
     │ Tool: sqlmap                 │
     │ Status: FAILED               │
     │ Return Code: 124 (timeout)   │
     │ stderr: "Timeout after 600s" │
     │                              │
     │ Analyze:                     │
     │ 1. Was execution successful? │
     │ 2. What went wrong?          │
     │ 3. Should we retry?          │
     │ 4. If retry, what to change? │
     │ 5. Next action?              │
     │                              │
     │ Respond in JSON:             │
     │ {                            │
     │   "success": false,          │
     │   "analysis": "...",         │
     │   "should_retry": true,      │
     │   "confidence": 0.7,         │
     │   "suggested_params": {}     │
     │ }                            │
     └──────────────────────────────┘

  3. Call LLM for reflection:
     → Llama-3 analyzes the failure
     → Returns structured JSON
     → Parse confidence score

  4. Check retry limits:
     ├─ Get retry_count for this tool
     ├─ Compare with max_retries (3)
     ├─ If retry_count >= max_retries:
     │   └─ Force should_retry=false
     └─ Prevents infinite retry loops

  5. Make decision:
     ┌─────────────────────────────────────┐
     │ IF SUCCESS                          │
     │  ├─ Reset failed_attempts to 0      │
     │  ├─ Continue to next reasoning      │
     │  └─ [Normal progress]               │
     │                                     │
     │ IF FAILURE:                         │
     │  ├─ IF should_retry AND retries OK  │
     │  │   ├─ Add strategy to retry list  │
     │  │   ├─ Continue to reasoning       │
     │  │   └─ [LLM will modify params]    │
     │  └─ ELSE (no retry)                 │
     │      ├─ Reset failed_attempts       │
     │      ├─ Continue forward            │
     │      └─ [Accept failure, move on]   │
     │                                     │
     │ TERMINATION CHECKS:                 │
     │  ├─ loop_count >= max_loops?        │
     │  ├─ failed_attempts > threshold?    │
     │  └─ [End execution if true]         │
     └─────────────────────────────────────┘

  6. Store reflection:
     {
         "step_number": 2,
         "executed_action": "sqlmap",
         "observation": "Timeout after 600s",
         "reflection": "SQLmap was too aggressive...",
         "confidence": 0.75,
         "should_retry": true,
         "next_action_suggestion": "retry with risk=1",
         "timestamp": 1234567890.0
     }

OUTPUT: Updated state with:
  ├─ reflections: [..., new reflection]
  ├─ should_continue: true/false
  ├─ termination_reason: optional explanation
  ├─ retry_strategies: updated with new attempts
  └─ failed_attempts: reset or incremented

KEY INNOVATION: RETRY LOGIC
────────────────────────────

Problem: Tool fails, but agent shouldn't give up immediately

Solution:
  1. Reflection analyzes WHY it failed
  2. Suggests DIFFERENT APPROACH
  3. Retry with MODIFIED PARAMETERS
  4. Track what's been tried (prevent loops)
  5. Give up after 3 attempts

Example:
  Attempt 1: sqlmap -u "target" --risk 3 --dbs
    → TIMEOUT
  Reflection: "Risk level too high, timeout"
  Attempt 2: sqlmap -u "target" --risk 1 -p "username"
    → SUCCESS
  Result: Vulnerability found through adaptation!

═══════════════════════════════════════════════════════════════════════════════
PART 5: TOOL INTEGRATIONS
═══════════════════════════════════════════════════════════════════════════════

[Nmap] Network Scanning
───────────────────────

Purpose: Identify open ports and services

Parameters:
  {
    "target": "192.168.1.100",     # Required
    "ports": "1-10000",             # Optional, default all
    "scan_type": "syn",             # "syn", "udp", "aggressive"
    "output_format": "normal"       # Output format
  }

Tool Command:
  nmap -sS -p 1-10000 -sV -oN - 192.168.1.100

Typical Output:
  80/tcp   open   http          Apache httpd
  443/tcp  open   https         Apache httpd
  3000/tcp open   nodejs        Node.js

Integration:
  1. Parsing: Extract port -> service mappings
  2. State Update: scanned_ports = {"80": "http", "443": "https", ...}
  3. Next Action: Decide which service to test


[SQLmap] SQL Injection Testing
───────────────────────────────

Purpose: Test for and exploit SQL injection vulnerabilities

Parameters:
  {
    "url": "http://target:3000/api/login",    # Required
    "method": "POST",                         # GET, POST
    "data": "username=test&password=test",    # POST data
    "dbs": true,                              # Enumerate databases
    "tables": true,                           # Enumerate tables
    "risk": "1"                               # 1=low, 2=med, 3=high
  }

Tool Command:
  sqlmap -u "http://target:3000/api/login" --method POST -d "..." --dbs --risk 1

Typical Output:
  [*] Testing for SQL injection
  [+] Found vulnerable parameter: username
  [+] Database: users, accounts, logs
  [+] Tables: admin, credentials, sessions

Integration:
  1. Trigger: After discovering web service
  2. Parameters: Extracted from curl responses
  3. Result: Store as SQL injection vulnerability
  4. Status: "identified", "exploited"


[Curl] HTTP/HTTPS Testing
──────────────────────────

Purpose: Manual HTTP requests, API probing, credential testing

Parameters:
  {
    "url": "http://target:3000/api/login",    # Required
    "method": "POST",                         # GET, POST, PUT, DELETE
    "headers": {"Content-Type": "application/json"},
    "data": '{"username":"admin","password":"test"}',
    "follow_redirects": true,
    "username": "admin",                      # Basic auth
    "password": "test"
  }

Tool Command:
  curl -X POST -H "Content-Type: application/json" -d '...' http://target:3000/api/login

Typical Output:
  {"status":"success","user_id":1,"role":"admin"}
  OR
  HTTP/1.1 401 Unauthorized

Integration:
  1. Reconnaissance: Discover endpoints
  2. Authentication: Test login credentials
  3. API Testing: Probe for common vulnerabilities
  4. Parsing: Extract useful responses


[Hydra] Credential Brute-forcing
─────────────────────────────────

Purpose: Test for weak credentials using wordlists

Parameters:
  {
    "target": "192.168.1.100",                # Required
    "service": "http-post",                   # Service type
    "username": "admin",                      # Single or list file
    "password_list": "/path/to/wordlist.txt", # Password wordlist
    "port": "3000"                            # Target port
  }

Tool Command:
  hydra -l admin -P /path/to/wordlist.txt -p 3000 -o - 192.168.1.100 http-post

Typical Output:
  [3000][http-post-form] host: 192.168.1.100   login: admin   password: password123

Integration:
  1. Trigger: After discovering login page
  2. Wordlists: Common passwords, weak credentials
  3. Result: Store successful credentials
  4. Status: "weak_credentials" vulnerability

═══════════════════════════════════════════════════════════════════════════════
PART 6: LANGGRAPH WORKFLOW
═══════════════════════════════════════════════════════════════════════════════

Graph Construction:

from langgraph.graph import StateGraph

graph = StateGraph(AgentState)

# Add nodes (functions that process state)
graph.add_node("reasoning", reasoning_node.invoke)
graph.add_node("execution", execution_node.invoke)
graph.add_node("reflection", reflection_node.invoke)
graph.add_node("end", end_node)

# Set entry point
graph.set_entry_point("reasoning")

# Add edges (transitions between nodes)
graph.add_edge("reasoning", "execution")
graph.add_edge("execution", "reflection")

# Conditional edge (decision point)
graph.add_conditional_edges(
    "reflection",
    should_continue_condition,  # Function that returns "continue" or "end"
    {
        "continue": "reasoning",  # Loop back
        "end": "end"              # Terminate
    }
)

graph.set_finish_point("end")

# Compile for execution
compiled_graph = graph.compile()

Execution Flow:

target = "192.168.1.100"
initial_state = create_initial_state(target)

# Run the graph
final_state = compiled_graph.invoke(initial_state)

# Access results
for vuln in final_state["vulnerabilities"]:
    print(f"Found: {vuln['type']} at {vuln['location']}")

═══════════════════════════════════════════════════════════════════════════════
PART 7: MEMORY MANAGEMENT (CHROMADB RAG)
═══════════════════════════════════════════════════════════════════════════════

Purpose:
  - Long-term memory of findings
  - Retrieve relevant past assessments
  - Enable learning across multiple targets

Components:

RAGManager:
  ├─ Store findings in ChromaDB vector database
  ├─ Retrieve similar findings by semantic search
  ├─ Track what's been tried before
  └─ Enable adaptive reasoning

Storage:

1. Vulnerabilities:
   Query: "SQL injection vulnerabilities"
   Store: ← VulnerabilityFinding
   Index: In ChromaDB
   Retrieve: During reasoning for context

2. Executions:
   Query: "Nmap scan of port 3000"
   Store: ← ToolExecution
   Index: Searchable by tool/target
   Retrieve: Similar tool runs

3. Strategies:
   Query: "SQLmap timeout recovery"
   Store: ← Reflection (what worked)
   Index: By tool name and strategy
   Retrieve: Adaptive retry parameters

Retrieval in Reasoning:

```python
# In ReasoningNode
relevant_docs = rag_manager.retrieve(
    query="SQL injection vulnerabilities for port 3000",
    k=5  # Get top 5 similar findings
)

# Add to prompt:
memory_section = "### RELEVANT PAST FINDINGS\n"
for doc in relevant_docs:
    memory_section += doc + "\n"
```

═══════════════════════════════════════════════════════════════════════════════
PART 8: SYSTEM PROMPT STRATEGY
═══════════════════════════════════════════════════════════════════════════════

Core Principle: Structure prompts to enforce ReAct format and prevent hallucination

REASONING PROMPT STRUCTURE:

```
You are The Red Agent.
Your role: Autonomous penetration testing.

### TARGET INFORMATION
Host: 192.168.1.100
Type: IP Address

### AVAILABLE TOOLS
- nmap: Network scanning
- sqlmap: SQL injection testing
- curl: HTTP requests
- hydra: Credential brute-forcing
- analyze_scan: Parse results
- check_memory: Retrieve past findings

### MANDATORY RESPONSE FORMAT
Thought: <Your reasoning>
Action: <Tool name from AVAILABLE TOOLS ONLY>
Action Input: <JSON parameters>

CRITICAL RULES:
1. Only use tools from AVAILABLE TOOLS
2. Do NOT invent or hallucinate tools
3. Every response MUST follow Thought/Action/Input format
4. If unsure, use "check_memory" first

### EXECUTION HISTORY
1. nmap: SUCCESS (found ports 80, 443, 3000)
2. curl: FAILED (timeout on port 80)

### CURRENT PLAN
Step 1: ✓ Scan network ports
Step 2: ○ Test for SQL injection
Step 3: ○ Brute-force credentials

### TASK
Decide the NEXT action. Think carefully about:
1. What's been tried?
2. What services are open?
3. What vulnerabilities found?
4. What's the logical next step?

Respond in ReAct format (Thought, Action, Action Input):
```

Why This Works:

1. WHITELIST ENFORCEMENT
   - Tools listed BEFORE inference
   - LLM sees boundaries clearly
   - Cannot invent new tools

2. FORMAT BINDING
   - Mandatory format repeated multiple times
   - Regexes enforce structure
   - Parse errors → controlled retry

3. CONTEXT GROUNDING
   - Execution history prevents confusion
   - Clear current state
   - Reduces hallucination

4. EXPLICIT CONSTRAINTS
   - "CRITICAL RULES" section
   - Repetition of restrictions
   - Clear consequences

REFLECTION PROMPT STRUCTURE:

```
Analyze this tool execution:

Tool: sqlmap
Status: FAILED
Return Code: 124
stderr: "Timeout after 600s"
stdout: [partial output]

Provide JSON analysis:
{
    "success": true/false,
    "analysis": "What happened",
    "should_retry": true/false,
    "retry_reason": "Why retry or not",
    "suggested_parameters": {"modified_params": "..."},
    "next_action": "tool_name or strategy",
    "confidence": 0.0-1.0
}

Only respond with valid JSON.
```

═══════════════════════════════════════════════════════════════════════════════
PART 9: ERROR HANDLING & RECOVERY
═══════════════════════════════════════════════════════════════════════════════

ERROR TYPES:

1. PARSING ERRORS
   - LLM output doesn't match ReAct format
   - Recovery: Force next cycle to try again
   - Prevention: Regex validation + repetition in prompt

2. VALIDATION ERRORS
   - Tool name not in VALID_TOOLS
   - Recovery: Reflect and choose valid tool
   - Prevention: Whitelist checking in ReasoningNode

3. EXECUTION ERRORS
   - Tool crashes or times out
   - Recovery: Reflection analyzes and decides retry
   - Prevention: Timeout enforcement + exception handling

4. REFLECTION ERRORS
   - LLM can't analyze results
   - Recovery: Use default decision logic
   - Prevention: Structured JSON output requirement

5. MEMORY ERRORS
   - ChromaDB connection fails
   - Recovery: Continue without retrieval
   - Prevention: Try/except blocks

RETRY MECHANISM:

Max Retries Per Tool: 3

Attempt 1:
  sqlmap -u target --dbs --risk 3
  → TIMEOUT

Reflection:
  "Risk too high, timed out after 600s"
  should_retry: true
  retry_count: 1/3

Attempt 2:
  sqlmap -u target --dbs --risk 1
  → SUCCESS

Result:
  Vulnerability found, reset counter

Timeout Backoff:

timeout = base_timeout * (retry_backoff_factor ^ attempts)

Example (base=600s, factor=1.5):
  Attempt 1: 600s
  Attempt 2: 900s  (1.5x)
  Attempt 3: 1350s (2.25x)
  Give up: Exceeded max

═══════════════════════════════════════════════════════════════════════════════
PART 10: SECURITY & SAFETY
═══════════════════════════════════════════════════════════════════════════════

PREVENTING HALLUCINATIONS:

1. TOOL WHITELIST
   ├─ Defined in ReasoningNode.VALID_TOOLS
   ├─ Checked BEFORE agent responds
   ├─ Validated after parsing
   └─ Rejected if not found

2. FORMAT ENFORCEMENT
   ├─ Regex validation of Thought/Action/Input
   ├─ JSON parsing for parameters
   ├─ Error on malformed response
   └─ Controlled retry on failure

3. PROMPT STRUCTURE
   ├─ Tools listed at top (pre-inference boundary)
   ├─ Rules repeated (binding)
   ├─ Explicit "do not" instructions
   └─ Clear consequences

PREVENTING COMMAND INJECTION:

1. NO SHELL EXECUTION
   ├─ subprocess.run() without shell=True
   ├─ No shell metacharacter interpretation
   ├─ Arguments passed as list, not string
   └─ Safe default: shell=False

2. PARAMETER VALIDATION
   ├─ Input checked before tool execution
   ├─ Reject suspicious patterns
   ├─ Sanitize if necessary
   └─ Log suspicious attempts

3. OUTPUT ISOLATION
   ├─ stdout/stderr captured
   ├─ No automatic echo/redirect
   ├─ Content passed to LLM as data
   └─ Not interpreted as code

RESOURCE PROTECTION:

1. TIMEOUT ENFORCEMENT
   ├─ Every tool has max_timeout
   ├─ Default: 300-600 seconds
   ├─ Subprocess.TimeoutExpired caught
   └─ Graceful termination

2. RESOURCE LIMITS
   ├─ Max execution steps: 15
   ├─ Max consecutive failures: 3
   ├─ Max retries per tool: 3
   └─ Max total time: 3600s per target

3. MONITORING
   ├─ Log all executions
   ├─ Track resource usage
   ├─ Alert on anomalies
   └─ Graceful degradation

═══════════════════════════════════════════════════════════════════════════════
PART 11: EXTENSIBILITY
═══════════════════════════════════════════════════════════════════════════════

Adding a New Tool:

Step 1: Create tool wrapper

class MyNewTool(BaseTool):
    def __init__(self):
        super().__init__("my_tool", timeout=300)
    
    def execute(self, params):
        target = params.get("target")
        command = ["my_tool", "--output", "-", target]
        return self._run_command(command)

Step 2: Register in ToolFactory

self.tools["my_tool"] = MyNewTool()

Step 3: Add to VALID_TOOLS

VALID_TOOLS = {
    "nmap": "...",
    "my_tool": "Description of my tool"
}

Step 4: Test

# LLM will see the tool and can use it
# It will be validated and executed normally

═══════════════════════════════════════════════════════════════════════════════
PART 12: DEPLOYMENT & OPERATIONS
═══════════════════════════════════════════════════════════════════════════════

Local Development:

1. Install dependencies: pip install -r requirements.txt
2. Start Ollama: ollama serve
3. Run: python main.py 192.168.1.100

Docker Deployment:

FROM python:3.10

WORKDIR /app
COPY . /app
RUN pip install -r requirements.txt

ENV OLLAMA_BASE_URL=http://ollama:11434

CMD ["python", "main.py", "target.local"]

Production Considerations:

1. ISOLATION
   - Run in separate container
   - Restrict network access
   - Firewall rules

2. MONITORING
   - Log all actions
   - Alert on errors
   - Track metrics

3. SECURITY
   - API authentication
   - Audit trails
   - Result encryption

4. PERSISTENCE
   - Back up ChromaDB
   - Version reports
   - Archive findings

═══════════════════════════════════════════════════════════════════════════════

END OF ARCHITECTURE DOCUMENT

For implementation details, see IMPLEMENTATION_GUIDE.py
For configuration, see config/config.py
For quick start, see README.md
"""

if __name__ == "__main__":
    print(__doc__)
