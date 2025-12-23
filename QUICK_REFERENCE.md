"""
THE RED AGENT - QUICK REFERENCE GUIDE

╔═════════════════════════════════════════════════════════════════════════════╗
║                        AGENT STATE FLOW DIAGRAM                            ║
╚═════════════════════════════════════════════════════════════════════════════╝

┌─────────────────┐
│  TARGET INPUT   │
│  192.168.1.100  │
└────────┬────────┘
         │
         ▼
    ┌─────────────────────────────────────────┐
    │   CREATE INITIAL AGENT STATE            │
    │  • Empty execution_history              │
    │  • Empty reasoning_history              │
    │  • loop_count = 0                       │
    │  • failed_attempts = 0                  │
    └────────┬────────────────────────────────┘
             │
             ▼
    ┌────────────────────────────────────────────────────┐
    │        REASONING NODE (LLM Inference)              │
    │  ┌──────────────────────────────────────────────┐  │
    │  │ 1. Retrieve context from ChromaDB            │  │
    │  │ 2. Build prompt with:                        │  │
    │  │    - Target: 192.168.1.100                   │  │
    │  │    - Available Tools (whitelist)              │  │
    │  │    - Execution History                       │  │
    │  │    - ReAct Format Rules                      │  │
    │  │ 3. Call Ollama Llama-2                       │  │
    │  │ 4. Parse: Thought/Action/Input               │  │
    │  │ 5. Validate: Action in VALID_TOOLS?          │  │
    │  │ 6. Return: parsed_action + input              │  │
    │  └──────────────────────────────────────────────┘  │
    │                                                    │
    │  OUTPUT: parsed_action="nmap"                      │
    │          parsed_action_input={"target":"192..."}   │
    └────────┬─────────────────────────────────────────┘
             │
             ▼
    ┌────────────────────────────────────────────────────┐
    │        EXECUTION NODE (Tool Running)               │
    │  ┌──────────────────────────────────────────────┐  │
    │  │ 1. Get tool from ToolFactory                 │  │
    │  │ 2. Execute: nmap -sS -p 1-10000 ...          │  │
    │  │ 3. Capture stdout/stderr/return_code          │  │
    │  │ 4. Create ToolExecution record                │  │
    │  │ 5. Add to execution_history                   │  │
    │  │ 6. Update state counters                      │  │
    │  └──────────────────────────────────────────────┘  │
    │                                                    │
    │  OUTPUT: execution_history = [nmap_result]        │
    │          last_execution = {tool, status, output}  │
    └────────┬─────────────────────────────────────────┘
             │
             ▼
    ┌────────────────────────────────────────────────────┐
    │        REFLECTION NODE (Analysis & Decision)       │
    │  ┌──────────────────────────────────────────────┐  │
    │  │ 1. Analyze: Was execution successful?        │  │
    │  │ 2. Call LLM: Analyze and decide              │  │
    │  │ 3. Parse: success/should_retry/confidence    │  │
    │  │ 4. Check: Retry limits                       │  │
    │  │ 5. Decide:                                   │  │
    │  │    ✓ Success → Reset, continue               │  │
    │  │    ✗ Fail → Retry or move on                 │  │
    │  │ 6. Check: Termination conditions?            │  │
    │  └──────────────────────────────────────────────┘  │
    │                                                    │
    │  OUTPUT: reflections = [analysis]                 │
    │          should_continue = true/false             │
    │          termination_reason = "..."               │
    └────────┬─────────────────────────────────────────┘
             │
             ▼
        ┌─────────────┐
        │  CONTINUE?  │
        └────┬────┬───┘
        YES  │    │  NO
             ▼    ▼
           LOOP  END
            ▲     │
            │     ▼
            │  ┌──────────────────────┐
            │  │  Final Report        │
            │  │  - Vulnerabilities   │
            │  │  - Exploited Service │
            │  │  - Recommendations   │
            │  └──────────────────────┘
            │
            └─ Back to Reasoning


╔═════════════════════════════════════════════════════════════════════════════╗
║                     REFLECTION-BASED RETRY LOGIC                           ║
╚═════════════════════════════════════════════════════════════════════════════╝

Scenario: SQLmap Timeout Recovery

EXECUTION 1:
  Command: sqlmap -u "http://192.168.1.100:3000/api" --dbs --risk 3
  Status:  TIMEOUT
  Return:  124

REFLECTION:
  ┌─────────────────────────────────────────┐
  │ Tool: sqlmap                            │
  │ Status: FAILED (timeout)                │
  │ Analysis: "Risk level too aggressive"   │
  │ Should Retry: YES (attempt 1/3)         │
  │ Suggestion: Reduce risk to 1            │
  └─────────────────────────────────────────┘

EXECUTION 2 (ADAPTED):
  Command: sqlmap -u "http://192.168.1.100:3000/api" --dbs --risk 1
  Status:  SUCCESS
  Return:  0

RESULT:
  ✓ Vulnerability found through adaptation
  ✓ Agent learned and recovered from failure
  ✓ Reset failed_attempts counter


╔═════════════════════════════════════════════════════════════════════════════╗
║                        AGENT STATE AT A GLANCE                             ║
╚═════════════════════════════════════════════════════════════════════════════╝

Initial State:
  {
    "target": "192.168.1.100",
    "loop_count": 0,
    "execution_history": [],
    "reflections": [],
    "vulnerabilities": [],
    ...
  }

After Cycle 1 (Nmap):
  {
    ...
    "loop_count": 1,
    "execution_history": [nmap_result],
    "scanned_ports": {"80": "http", "443": "https", "3000": "nodejs"},
    "last_execution": nmap_result,
    ...
  }

After Cycle 2 (SQL Injection Test):
  {
    ...
    "loop_count": 2,
    "execution_history": [nmap_result, curl_result],
    "vulnerabilities": [sql_injection_vuln],
    "reflections": [nmap_reflection, curl_reflection],
    ...
  }

Final State (Complete Assessment):
  {
    ...
    "loop_count": 8,
    "termination_reason": "Completed assessment",
    "vulnerabilities": [8 findings],
    "execution_history": [8 executions],
    "reflections": [8 reflections],
    ...
  }


╔═════════════════════════════════════════════════════════════════════════════╗
║                      TOOL EXECUTION REFERENCE                              ║
╚═════════════════════════════════════════════════════════════════════════════╝

NMAP - Network Scanning
  Purpose:  Identify open ports and services
  Trigger:  First step of reconnaissance
  Timeout:  300 seconds
  Success:  return_code == 0
  Output:   Port listing with services
  Next:     SQL injection or credential testing

SQLMAP - SQL Injection Testing
  Purpose:  Test for SQL injection vulnerabilities
  Trigger:  After discovering web service
  Timeout:  600 seconds
  Success:  Successfully enumerated databases
  Output:   Database names, tables, columns
  Next:     Data extraction or authentication bypass

CURL - HTTP Testing
  Purpose:  Manual HTTP requests and API probing
  Trigger:  Discover endpoints, test auth
  Timeout:  30 seconds
  Success:  Unexpected response or access granted
  Output:   HTTP response, headers, body
  Next:     SQL injection testing or brute-forcing

HYDRA - Brute-Forcing
  Purpose:  Test weak credentials
  Trigger:  After finding login forms
  Timeout:  600 seconds
  Success:  Credentials found
  Output:   Valid username:password combination
  Next:     Post-exploitation or lateral movement


╔═════════════════════════════════════════════════════════════════════════════╗
║                    SYSTEM PROMPT KEY PRINCIPLES                            ║
╚═════════════════════════════════════════════════════════════════════════════╝

1. WHITELIST BOUNDARY (Pre-inference)
   ┌──────────────────────────────┐
   │ AVAILABLE TOOLS:             │ ← Listed BEFORE LLM inference
   │ - nmap                       │ ← LLM sees boundary clearly
   │ - sqlmap                     │
   │ - curl                       │
   │ - hydra                      │
   │ (NO OTHER TOOLS EXIST)       │
   └──────────────────────────────┘
   
   Effect: Cannot hallucinate non-existent tools

2. FORMAT BINDING (Repetition)
   ┌──────────────────────────────────┐
   │ MANDATORY FORMAT:                │ ← Stated once
   │ Thought: ...                     │
   │ Action: ...                      │
   │ Action Input: ...                │
   │                                  │
   │ CRITICAL RULES:                  │
   │ - Use only listed tools          │ ← Repeated
   │ - Follow format exactly          │
   │ - Every response must have all 3 │
   │                                  │
   │ YOUR TASK:                       │
   │ Respond in format above          │ ← Repeated again
   │ (Thought/Action/Input)           │
   └──────────────────────────────────┘
   
   Effect: Format enforced through repetition

3. CONTEXT GROUNDING (Execution History)
   ┌──────────────────────────────┐
   │ EXECUTION HISTORY:           │
   │ 1. nmap: SUCCESS            │ ← What's been done
   │ 2. curl: FAILED (timeout)   │
   │                              │
   │ CURRENT PLAN:               │
   │ Step 1: ✓ Scan ports         │ ← Where we are
   │ Step 2: ○ Test SQL injection │ ← Where we're going
   │                              │
   │ VULNERABILITIES FOUND:      │
   │ - None yet                   │ ← What we know
   └──────────────────────────────┘
   
   Effect: Grounds reasoning in concrete facts

4. EXPLICIT CONSTRAINTS (Do Not Do)
   ┌──────────────────────────────────┐
   │ DO NOT:                          │
   │ - Invent new tools               │ ← Clear prohibition
   │ - Ignore the mandatory format    │
   │ - Make assumptions about tools   │
   │                                  │
   │ IF UNSURE:                       │
   │ - Use "check_memory" tool        │ ← Safe fallback
   │ - Ask for clarification          │
   │ - Don't guess or improvise       │
   └──────────────────────────────────┘
   
   Effect: Prevents unauthorized behavior


╔═════════════════════════════════════════════════════════════════════════════╗
║                     HALLUCINATION PREVENTION LAYERS                        ║
╚═════════════════════════════════════════════════════════════════════════════╝

Layer 1: PROMPT DESIGN
  └─ Whitelist tools at top (pre-inference)
  └─ Repeat format rules
  └─ Ground with execution history

Layer 2: PARSING VALIDATION
  └─ Regex: Match exact Thought/Action/Input format
  └─ Exception handling: Graceful on parse failure
  └─ Fallback: JSON parsing for parameters

Layer 3: ACTION VALIDATION
  └─ Check: Is parsed_action in VALID_TOOLS?
  └─ Reject: Non-existent tools
  └─ Log: Suspicious attempts

Layer 4: EXECUTION ISOLATION
  └─ No shell interpretation
  └─ Arguments as list, not string
  └─ Output captured as data, not code

Layer 5: ERROR RECOVERY
  └─ Parse error → Forced reflection
  └─ Validation error → Error entry + retry
  └─ Never crashes, always recovers


╔═════════════════════════════════════════════════════════════════════════════╗
║                     EXTENDING WITH NEW TOOLS                               ║
╚═════════════════════════════════════════════════════════════════════════════╝

Step 1: Create Tool Wrapper
┌─────────────────────────────────────┐
│ from tools.tool_factory import      │
│   BaseTool                          │
│                                     │
│ class MyToolName(BaseTool):         │
│   def __init__(self):               │
│     super().__init__(               │
│       "my_tool_name",               │
│       timeout=300                   │
│     )                               │
│                                     │
│   def execute(self, params):        │
│     # Build command                 │
│     # Execute via _run_command()    │
│     # Return results                │
│     return {...}                    │
└─────────────────────────────────────┘

Step 2: Register in ToolFactory
┌─────────────────────────────────┐
│ self.tools["my_tool"] =         │
│   MyToolName()                  │
└─────────────────────────────────┘

Step 3: Add to VALID_TOOLS
┌─────────────────────────────────────┐
│ VALID_TOOLS = {                     │
│   "nmap": "...",                    │
│   "my_tool": "Description of tool"  │
│ }                                   │
└─────────────────────────────────────┘

Step 4: Test
┌─────────────────────────────────┐
│ LLM can now see and use the tool │
│ Will be validated and executed   │
└─────────────────────────────────┘


╔═════════════════════════════════════════════════════════════════════════════╗
║                       PROJECT FILE NAVIGATION                              ║
╚═════════════════════════════════════════════════════════════════════════════╝

📋 START HERE:
  README.md                    - Quick start (5 min read)
  DELIVERY_SUMMARY.md          - What was built

📚 UNDERSTAND SYSTEM:
  ARCHITECTURE.md              - Complete architecture (detailed)
  IMPLEMENTATION_GUIDE.py      - Examples and workflows

🔧 IMPLEMENTATION DETAILS:
  core/state.py                - AgentState definition
  core/nodes_reasoning.py      - LLM reasoning
  core/nodes_execution.py      - Tool execution
  core/nodes_reflection.py     - Error analysis & retry
  core/orchestrator.py         - LangGraph workflow
  tools/tool_factory.py        - Tool implementations
  memory/rag.py                - ChromaDB integration
  prompts/system_prompts.py    - LLM prompts

⚙️ CONFIGURATION:
  config/config.py             - All settings

🚀 RUN:
  main.py                      - Entry point


╔═════════════════════════════════════════════════════════════════════════════╗
║                          KEY CONCEPTS SUMMARY                              ║
╚═════════════════════════════════════════════════════════════════════════════╝

ReAct Loop:
  └─ Thought: Reason about target
  └─ Action: Decide which tool to use
  └─ Observation: Execute tool and get output

Self-Reflection:
  └─ Analyze execution results
  └─ Decide: Success or failure?
  └─ Decide: Retry with different params or move on?
  └─ Learn: Track what's been tried

AgentState:
  └─ Complete execution context
  └─ All history (reasoning, execution, reflection)
  └─ All findings (vulnerabilities, services)
  └─ Control flow (loop_count, should_continue)

Tool Whitelist:
  └─ Only tools in VALID_TOOLS can be used
  └─ Prevents hallucination of non-existent tools
  └─ Validated at multiple levels

ChromaDB Memory:
  └─ Stores all findings
  └─ Enables semantic search for context
  └─ Allows learning across multiple assessments

Retry Logic:
  └─ Tool fails → Reflection analyzes
  └─ Suggests different approach
  └─ Retries with modified parameters
  └─ Limits retries to prevent infinite loops


═════════════════════════════════════════════════════════════════════════════

This is a COMPLETE, PRODUCTION-READY autonomous penetration testing agent.

All code is modular, documented, and ready for deployment.

Start with README.md and follow the file navigation guide above.

═════════════════════════════════════════════════════════════════════════════
"""

if __name__ == "__main__":
    print(__doc__)
