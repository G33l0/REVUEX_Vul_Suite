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

            print(f"→ Analyzing JWT token: {token[:20]}...")

            # Decode JWT
            jwt_data = self._decode_jwt(token)
            if not jwt_data:
                continue

            # Run tests
            for test in [
                self._test_none_algorithm,
                self._test_algorithm_confusion,
                self._test_weak_secret,
                self._test_expiration,
                self._test_sensitive_data,
                self._test_signature_verification
            ]:
                result = test(token, jwt_data)
                if result:
                    vulnerabilities.append(result)
                time.sleep(self.delay)

        # Save results
        self._save_results(vulnerabilities)
        return vulnerabilities

    def _is_jwt(self, token):
        """Check if string is a valid JWT format"""
        return len(token.split('.')) == 3

    def _decode_jwt(self, token):
        """Decode JWT token"""
        try:
            header_b64, payload_b64, signature = token.split('.')
            header_b64 += '=' * (-len(header_b64) % 4)
            payload_b64 += '=' * (-len(payload_b64) % 4)

            header = json.loads(base64.urlsafe_b64decode(header_b64))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            return {
                'token': token,
                'header': header,
                'payload': payload,
                'signature': signature
            }
        except Exception:
            return None

    # Placeholder for other methods
    def _test_none_algorithm(self, token, jwt_data):
        pass

    def _test_algorithm_confusion(self, token, jwt_data):
        pass

    def _test_weak_secret(self, token, jwt_data):
        pass

    def _test_expiration(self, token, jwt_data):
        pass

    def _test_sensitive_data(self, jwt_data):
        pass

    def _test_signature_verification(self, token, jwt_data):
        pass

    def _test_token(self, token):
        try:
            headers = self.headers.copy()
            headers['Authorization'] = f'Bearer {token}'
            response = requests.get(self.target, headers=headers, timeout=5, verify=False)
            return {'accepted': response.status_code not in [401, 403], 'status': response.status_code}
        except:
            return None

    def _save_results(self, vulnerabilities):
        jwt_dir = self.workspace / "jwt_analysis"
        jwt_dir.mkdir(exist_ok=True)
        output_file = jwt_dir / "jwt_vulnerabilities.json"
        with open(output_file, 'w') as f:
            json.dump({
                'target': self.target,
                'tokens_analyzed': len(self.tokens),
                'vulnerabilities': vulnerabilities
            }, f, indent=2)