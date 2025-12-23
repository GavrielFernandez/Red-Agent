"""
System Prompts for The Red Agent
Carefully crafted to enforce ReAct format and prevent hallucination
"""

from typing import List, Dict, Any

REACT_FORMAT_INSTRUCTION = """
### RESPONSE FORMAT (MANDATORY)
You MUST follow this exact format for every response:

Thought: <Your reasoning about what to do next>
Action: <Tool name from AVAILABLE TOOLS ONLY>
Action Input: <JSON or plain parameters for the tool>

CRITICAL RULES:
1. Only use tools from the AVAILABLE TOOLS list
2. Do NOT invent or hallucinate tools
3. Every response MUST have Thought, Action, and Action Input sections
4. Action must be a SINGLE WORD from the available tools
5. If you don't know what to do, use "analyze_scan" or "check_memory" first
6. If a tool failed, acknowledge it and try a different approach
"""

def get_reasoning_prompt(state: "AgentState", available_tools: Dict[str, str]) -> str:
    """
    Build the reasoning prompt for the ReAct loop.
    
    Components:
    1. System role
    2. Target information
    3. Available tools (strict whitelist)
    4. Execution history (context)
    5. ReAct format instruction
    6. Current objective
    """
    
    # Build available tools section
    tools_section = "### AVAILABLE TOOLS\n"
    for tool_name, description in available_tools.items():
        tools_section += f"- {tool_name}: {description}\n"
    
    # Build execution history section
    history_section = "### EXECUTION HISTORY\n"
    if state["execution_history"]:
        for i, execution in enumerate(state["execution_history"][-5:], 1):  # Last 5 executions
            history_section += f"{i}. {execution['tool_name']}: {execution['status'].value}\n"
            if execution["stderr"]:
                history_section += f"   Error: {execution['stderr'][:100]}...\n"
    else:
        history_section += "No executions yet.\n"
    
    # Build vulnerabilities found section
    vulns_section = "### DISCOVERED VULNERABILITIES\n"
    if state["vulnerabilities"]:
        for vuln in state["vulnerabilities"]:
            vulns_section += f"- [{vuln['severity']}] {vuln['type']} at {vuln['location']}\n"
    else:
        vulns_section += "None yet.\n"
    
    # Build memory context section
    memory_section = "### RELEVANT PAST FINDINGS\n"
    if state["relevant_context"]:
        for i, doc in enumerate(state["relevant_context"][:3], 1):
            memory_section += f"{i}. {doc[:150]}...\n"
    else:
        memory_section += "No relevant past findings.\n"
    
    # Build current plan section
    plan_section = "### CURRENT ATTACK PLAN\n"
    if state["plan_steps"]:
        for i, step in enumerate(state["plan_steps"], 1):
            completed = "✓" if i - 1 < state["current_step_index"] else "○"
            plan_section += f"{completed} Step {i}: {step}\n"
    else:
        plan_section += "No plan formulated yet. Consider formulating one.\n"
    
    # Build open services section
    services_section = "### SCANNED SERVICES\n"
    if state["scanned_ports"]:
        for port, service in list(state["scanned_ports"].items())[:10]:
            services_section += f"- Port {port}: {service}\n"
    else:
        services_section += "No services scanned yet.\n"
    
    # Determine the objective based on current state
    objective = _determine_objective(state)
    
    prompt = f"""You are The Red Agent, an autonomous penetration testing system.
Your role: Systematically scan and test the security of the target system.

### TARGET INFORMATION
Host: {state['target']}
Type: {state['target_type']}
Description: {state['target_description'] or 'No additional context'}

{tools_section}

{REACT_FORMAT_INSTRUCTION}

{history_section}

{services_section}

{plan_section}

{vulns_section}

{memory_section}

### CURRENT OBJECTIVE
{objective}

### YOUR TASK
Decide the NEXT action to take. Think carefully about:
1. What has already been tried?
2. What services are open?
3. What vulnerabilities have been identified?
4. What's the next logical step in the penetration test?
5. Are you making progress or stuck?

Now, respond in the ReAct format (Thought, Action, Action Input):
"""
    
    return prompt


def get_reflection_prompt(state: "AgentState") -> str:
    """
    Build the reflection prompt for analyzing execution results.
    
    The LLM analyzes:
    1. Was the tool execution successful?
    2. What did we learn?
    3. Should we retry with different parameters?
    4. What should we try next?
    """
    
    execution = state["last_execution"]
    if not execution:
        return "No execution to reflect on."
    
    # Summarize the execution
    execution_summary = f"""
Tool: {execution['tool_name']}
Status: {execution['status'].value}
Return Code: {execution['return_code']}
Execution Time: {execution['execution_time']:.2f}s
Failed Attempts: {execution['retry_count']}

stdout (first 300 chars):
{execution['stdout'][:300] if execution['stdout'] else '[empty]'}

stderr (first 300 chars):
{execution['stderr'][:300] if execution['stderr'] else '[empty]'}
"""
    
    prompt = f"""You are reflecting on a tool execution result.

{execution_summary}

### REFLECTION TASK
Analyze the tool execution:
1. Was this execution successful? (yes/no)
2. What did we learn from this execution?
3. If it failed, what went wrong?
4. Should we retry this tool with different parameters?
5. If we retry, what parameters should change?
6. What should be our next action? (tool name or strategy change)

Provide your analysis in JSON format:
{{
    "success": true/false,
    "analysis": "What happened",
    "should_retry": true/false,
    "retry_reason": "Why retry or why not",
    "suggested_parameters": {{"param": "value"}},
    "next_action": "next tool or strategy",
    "confidence": 0.0-1.0
}}

Respond only with valid JSON:
"""
    
    return prompt


def get_planning_prompt(state: "AgentState") -> str:
    """
    Prompt for formulating an initial attack plan.
    """
    
    prompt = f"""You are planning a penetration test against: {state['target']}

Target Type: {state['target_type']}
Scanned Ports: {', '.join(state['scanned_ports'].keys()) if state['scanned_ports'] else 'Not scanned yet'}

### PLANNING TASK
Create a structured attack plan with clear steps:

1. What information gathering should we do?
2. What services/ports should we target?
3. What attack vectors are most likely to succeed?
4. In what order should we attempt exploits?
5. What's our backup strategy if initial attempts fail?

Respond with a JSON plan:
{{
    "plan_title": "Overall strategy",
    "plan_description": "High-level approach",
    "steps": [
        "Step 1: ...",
        "Step 2: ...",
        "Step 3: ...",
        ...
    ],
    "priority_targets": ["service1", "service2"],
    "estimated_duration": "15-30 minutes"
}}

Respond only with valid JSON:
"""
    
    return prompt


def _determine_objective(state: "AgentState") -> str:
    """
    Determine the current objective based on agent state.
    """
    
    if not state["current_plan"]:
        return "OBJECTIVE: Formulate an initial attack plan based on target info."
    
    if not state["scanned_ports"]:
        return "OBJECTIVE: Scan the target to identify open ports and services."
    
    if not state["vulnerabilities"]:
        return "OBJECTIVE: Analyze scanned services for potential vulnerabilities."
    
    if state["exploited_services"]:
        return f"OBJECTIVE: Continue testing. You've already exploited {', '.join(state['exploited_services'][:3])}. " \
               f"Look for more vulnerabilities or deeper access."
    
    return "OBJECTIVE: Identify and exploit vulnerabilities in the target system."


def get_reporting_prompt(state: "AgentState") -> str:
    """
    Prompt for generating the final report content.
    """
    
    prompt = f"""Generate a professional penetration test report for: {state['target']}

### FINDINGS SUMMARY
Vulnerabilities Found: {len(state['vulnerabilities'])}
Services Exploited: {', '.join(state['exploited_services']) if state['exploited_services'] else 'None'}

### VULNERABILITIES
"""
    
    for vuln in state["vulnerabilities"]:
        prompt += f"- [{vuln['severity']}] {vuln['type']}: {vuln['description']}\n"
    
    prompt += """

### REPORT GENERATION TASK
Create an executive summary for the report:
1. Key findings (critical issues first)
2. Risk assessment
3. Recommendations for remediation
4. Timeline of testing activities

Respond with a JSON report:
{
    "title": "Penetration Test Report",
    "executive_summary": "...",
    "risk_level": "Critical/High/Medium/Low",
    "key_findings": ["..."],
    "recommendations": ["..."],
    "testing_timeline": "..."
}

Respond only with valid JSON:
"""
    
    return prompt
