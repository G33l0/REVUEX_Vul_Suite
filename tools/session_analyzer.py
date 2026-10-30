#!/usr/bin/env python3
"""
REVUEX - Session Analyzer
Session Management Vulnerability Detection

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
Session testing should only be performed with test accounts you control.
"""

import requests
import time
import json
import re
import math
import urllib3
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import hashlib
from collections import Counter

# Suppress insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SessionAnalyzer:
    """
    Session Management Vulnerability Scanner
    
    Features:
    - Session token entropy analysis
    - Session fixation detection
    - Cookie security flags (HttpOnly, Secure, SameSite)
    - Session timeout testing
    - Concurrent session limits
    - Session token predictability
    - Token reuse detection
    - Session hijacking vectors
    """

    def __init__(self, target: str, workspace: Path, delay: float = 5.0):
        """
        Initialize Session Analyzer
        """
        self.target = target
        self.workspace = Path(workspace)
        self.delay = delay
        
        # Safety limits
        self.max_requests = 80
        self.request_count = 0
        self.timeout = 10
        
        self.headers = {
            'User-Agent': 'REVUEX-SessionAnalyzer/1.0 (Security Research; +https://github.com/G33L0)',
        }
        
        self.vulnerabilities = []
        self.manual_checks = []
        self.collected_tokens = []

    @staticmethod
    def _is_session_cookie(name: str) -> bool:
        """Only session/auth cookies warrant HttpOnly/Secure 'high' findings.
        Flagging analytics/consent/CSRF-display cookies produced false positives."""
        n = (name or '').lower()
        keywords = ['session', 'sess', 'sid', 'auth', 'token', 'jwt',
                    'login', 'user', 'account', 'remember', 'phpsessid',
                    'jsessionid', 'asp.net', 'connect.sid']
        return any(k in n for k in keywords)

    def scan(self) -> List[Dict[str, Any]]:
        """Main session analysis method"""
        print(f"\n{'='*60}")
        print(f"🔐 REVUEX Session Analyzer")
        print(f"{'='*60}")
        print(f"Target: {self.target}")
        print(f"Safety Delay: {self.delay}s")
        print(f"Max Requests: {self.max_requests}")
        print(f"{'='*60}\n")
        
        print("⚠️  IMPORTANT:")
        print("   • Use ONLY test accounts you control")
        print("   • Do not test on production user sessions")
        print("   • Tests are passive observation only\n")
        
        # Test 1: Cookie security flags
        print("🍪 Test 1: Cookie Security Analysis")
        self._test_cookie_security()
        time.sleep(self.delay)
        
        # Test 2: Token entropy
        print("\n🎲 Test 2: Session Token Entropy")
        self._test_token_entropy()
        time.sleep(self.delay)
        
        # Test 3: Session fixation
        print("\n📌 Test 3: Session Fixation")
        self._test_session_fixation()
        time.sleep(self.delay)
        
        # Test 4: Token predictability
        print("\n🔮 Test 4: Token Predictability")
        self._test_token_predictability()
        time.sleep(self.delay)
        
        # Test 5: Concurrent sessions
        print("\n👥 Test 5: Concurrent Session Limits")
        self._test_concurrent_sessions()
        time.sleep(self.delay)
        
        # Test 6: Session timeout
        print("\n⏱️  Test 6: Session Timeout")
        self._test_session_timeout()
        
        # Save results
        self._save_results()
        
        print(f"\n{'='*60}")
        print(f"✅ Scan Complete")
        print(f"Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"Requests: {self.request_count}/{self.max_requests}")
        print(f"{'='*60}\n")
        
        return self.vulnerabilities

    def _test_cookie_security(self):
        """Test cookie security flags"""
        print("   Analyzing cookie security flags...")
        
        response = self._make_request(self.target)
        
        if not response:
            print("   ⚠️  Could not retrieve cookies")
            return
        
        cookies = response.cookies
        set_cookie_headers = response.headers.get('Set-Cookie', '')
        
        if not cookies and not set_cookie_headers:
            print("   ℹ️  No cookies set")
            return
        
        issues = []

        # Check each cookie
        for cookie in cookies:
            cookie_name = cookie.name

            # Only flag security-flag issues on actual session/auth cookies.
            # Non-session cookies (analytics, consent, display tokens) do not
            # carry session risk and were a major source of false positives.
            if not self._is_session_cookie(cookie_name):
                continue

            # Check HttpOnly flag
            if not cookie.has_nonstandard_attr('HttpOnly'):
                issues.append({
                    'cookie': cookie_name,
                    'issue': 'Missing HttpOnly flag',
                    'severity': 'high',
                    'impact': 'Cookie accessible via JavaScript - XSS can steal session'
                })
            
            # Check Secure flag
            if not cookie.secure:
                issues.append({
                    'cookie': cookie_name,
                    'issue': 'Missing Secure flag',
                    'severity': 'high',
                    'impact': 'Cookie transmitted over HTTP - MITM can intercept'
                })
            
            # Check SameSite
            if not cookie.has_nonstandard_attr('SameSite'):
                issues.append({
                    'cookie': cookie_name,
                    'issue': 'Missing SameSite attribute',
                    'severity': 'medium',
                    'impact': 'Vulnerable to CSRF attacks'
                })
        
        if issues:
            vuln = {
                'type': 'Session Management - Insecure Cookies',
                'severity': 'high',
                'url': self.target,
                'issues': issues,
                'description': 'Session cookies missing critical security flags',
                'evidence': f'{len(issues)} cookie security issues found',
                'steps_to_reproduce': [
                    f"Navigate to: {self.target}",
                    "Inspect cookies in browser DevTools",
                    "Check security flags",
                    "Missing: HttpOnly, Secure, SameSite"
                ],
                'poc': f"""#!/usr/bin/env python3
# Cookie Security Analysis
import requests
response = requests.get("{self.target}")
for cookie in response.cookies:
    print(f"Cookie: {{cookie.name}}")
    print(f"  HttpOnly: {{cookie.has_nonstandard_attr('HttpOnly')}}")
    print(f"  Secure: {{cookie.secure}}")
    print(f"  SameSite: {{cookie.get_nonstandard_attr('SameSite', 'None')}}")
    print()""",
                'remediation': [
                    'Set HttpOnly flag on ALL session cookies',
                    'Set Secure flag (HTTPS only)',
                    'Set SameSite=Strict or Lax',
                    'Example: Set-Cookie: session=xyz; HttpOnly; Secure; SameSite=Strict'
                ],
                'tags': ['session', 'cookies', 'high']
            }
            self.vulnerabilities.append(vuln)
            print(f"   ✓ Found {len(issues)} cookie security issues")
        else:
            print("   ✓ Cookies properly secured")

    def _test_token_entropy(self):
        """Test session token entropy"""
        print("   Calculating token entropy...")
        
        for i in range(5):
            if self.request_count >= self.max_requests:
                break
            response = self._make_request(self.target)
            if response and response.cookies:
                for cookie in response.cookies:
                    if 'session' in cookie.name.lower() or 'token' in cookie.name.lower():
                        self.collected_tokens.append(cookie.value)
            time.sleep(1)
        
        if not self.collected_tokens:
            print("   ℹ️  No session tokens found")
            return
        
        entropy_scores = [self._calculate_entropy(t) for t in self.collected_tokens]
        avg_entropy = sum(entropy_scores) / len(entropy_scores)
        print(f"   Average token entropy: {avg_entropy:.2f} bits")
        
        if avg_entropy < 64:
            vuln = {
                'type': 'Session Management - Weak Token Entropy',
                'severity': 'critical',
                'url': self.target,
                'average_entropy': f'{avg_entropy:.2f} bits',
                'description': f'Session tokens have insufficient entropy ({avg_entropy:.2f} bits).',
                'sample_tokens': self.collected_tokens[:3],
                'remediation': ['Use cryptographically secure random generator', 'Minimum 128 bits of entropy'],
                'tags': ['session', 'entropy', 'critical']
            }
            self.vulnerabilities.append(vuln)
            print(f"   ✓ VULNERABLE: Weak entropy ({avg_entropy:.2f} bits)")
        else:
            print(f"   ✓ Strong entropy ({avg_entropy:.2f} bits)")

    def _test_session_fixation(self):
        """Session fixation cannot be confirmed without an authenticated login
        flow (compare the session ID before and after login). This previously
        appended a fabricated 'high' finding for every target. It is now recorded
        as a manual check only."""
        print("   Session fixation requires a login flow -> manual check")
        self.manual_checks.append({
            'type': 'Session Management - Session Fixation',
            'severity': 'info',
            'confidence': 'manual-verification-required',
            'url': self.target,
            'how_to_confirm': ('Capture the session cookie before logging in, '
                               'authenticate, then check whether the server issued '
                               'a NEW session ID. If the pre-login ID is still valid '
                               'post-login, it is vulnerable.'),
            'tags': ['session', 'fixation', 'manual', 'unconfirmed']
        })

    def _test_token_predictability(self):
        """Test if tokens are predictable"""
        print("   Testing token predictability...")
        if len(self.collected_tokens) < 3:
            print("   ℹ️  Insufficient tokens for analysis")
            return
        
        patterns_found = []
        if self._has_sequential_pattern(self.collected_tokens): patterns_found.append('Sequential increments detected')
        if self._has_timestamp_pattern(self.collected_tokens): patterns_found.append('Timestamp-based generation')
        if self._has_repeated_substrings(self.collected_tokens): patterns_found.append('Repeated substrings')
        
        if patterns_found:
            vuln = {
                'type': 'Session Management - Predictable Tokens',
                'severity': 'critical',
                'url': self.target,
                'patterns': patterns_found,
                'tags': ['session', 'predictable']
            }
            self.vulnerabilities.append(vuln)
            print(f"   ✓ VULNERABLE: Predictable patterns found")
        else:
            print("   ✓ No obvious patterns detected")

    def _test_concurrent_sessions(self):
        """Concurrent-session limits cannot be measured without authenticating
        the same account from multiple clients. Recorded as a manual check
        instead of a fabricated finding."""
        print("   Concurrent session limits require login -> manual check")
        self.manual_checks.append({
            'type': 'Session Management - Concurrent Session Limits',
            'severity': 'info',
            'confidence': 'manual-verification-required',
            'url': self.target,
            'how_to_confirm': ('Log in as the same user from two clients. If both '
                               'sessions remain valid with no limit/notification, '
                               'note the policy. Whether this is a vulnerability is '
                               'application-dependent.'),
            'tags': ['session', 'concurrent', 'manual', 'unconfirmed']
        })

    def _test_session_timeout(self):
        """Session timeout requires observing an authenticated session over time.
        Recorded as a manual check instead of a fabricated finding."""
        print("   Session timeout requires a timed login session -> manual check")
        self.manual_checks.append({
            'type': 'Session Management - Timeout Policy',
            'severity': 'info',
            'confidence': 'manual-verification-required',
            'url': self.target,
            'how_to_confirm': ('Authenticate, leave the session idle, and test '
                               'whether it still works after the expected timeout. '
                               'Check for both idle and absolute timeouts.'),
            'tags': ['session', 'timeout', 'manual', 'unconfirmed']
        })

    def _calculate_entropy(self, token: str) -> float:
        """Calculate Shannon entropy of token"""
        if not token: return 0
        freq = Counter(token)
        length = len(token)
        entropy = 0
        for count in freq.values():
            p = count / length
            if p > 0: entropy -= p * math.log2(p)
        return entropy * length

    def _has_sequential_pattern(self, tokens: List[str]) -> bool:
        numeric_parts = []
        for token in tokens[:5]:
            numbers = re.findall(r'\d+', token)
            if numbers: numeric_parts.append(int(numbers[0]))
        if len(numeric_parts) >= 3:
            diffs = [numeric_parts[i+1] - numeric_parts[i] for i in range(len(numeric_parts)-1)]
            if len(set(diffs)) == 1: return True
        return False

    def _has_timestamp_pattern(self, tokens: List[str]) -> bool:
        for token in tokens[:5]:
            if re.search(r'\d{10,13}', token): return True
        return False

    def _has_repeated_substrings(self, tokens: List[str]) -> bool:
        if len(tokens) < 3: return False
        substrings = []
        for token in tokens[:5]:
            for i in range(len(token) - 3):
                substrings.append(token[i:i+4])
        freq = Counter(substrings)
        for substring, count in freq.items():
            if count >= 3: return True
        return False

    def _make_request(self, url: str) -> Optional[requests.Response]:
        if self.request_count >= self.max_requests: return None
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False)
            self.request_count += 1
            return response
        except:
            return None

    def _save_results(self):
        output_dir = self.workspace / "session_analysis"
        output_dir.mkdir(exist_ok=True, parents=True)
        safe_target = re.sub(r'[^\w\-]', '_', self.target)
        output_file = output_dir / f"{safe_target}_session.json"
        with open(output_file, 'w') as f:
            json.dump({
                'scanner': 'SessionAnalyzer',
                'target': self.target,
                'tokens_analyzed': len(self.collected_tokens),
                'vulnerabilities': self.vulnerabilities,
                'manual_checks': self.manual_checks
            }, f, indent=2)
        print(f"\n💾 Saved: {output_file}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python session_analyzer.py <target_url>")
        sys.exit(1)
    
    scanner = SessionAnalyzer(sys.argv[1], Path("revuex_workspace"), delay=5.0)
    scanner.scan()
