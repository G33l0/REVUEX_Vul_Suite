#!/usr/bin/env python3
"""
REVUEX - CSRF Tester
Cross-Site Request Forgery Detection

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
"""

import requests
import time
import json
import re
import urllib3
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# Disable warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CSRFTester:
    """
    CSRF Vulnerability Scanner
    
    Features:
    - CSRF token presence detection
    - Token entropy analysis
    - Token reuse testing
    - SameSite cookie analysis
    - Referer validation testing
    - Custom header requirements
    """

    def __init__(self, target: str, workspace: Path, delay: float = 5.0):
        """
        Initialize CSRF Tester
        """
        self.target = target
        self.workspace = Path(workspace)
        self.delay = delay
        
        # Safety limits
        self.max_requests = 50
        self.request_count = 0
        self.timeout = 10
        
        self.headers = {
            'User-Agent': 'REVUEX-CSRFTester/1.0 (Security Research; +https://github.com/G33L0)',
        }

        self.vulnerabilities = []
        self.manual_checks = []

    def scan(self) -> List[Dict[str, Any]]:
        """Main CSRF scanning method"""
        print(f"\n{'='*60}")
        print(f"🛡️  REVUEX CSRF Tester")
        print(f"{'='*60}")
        print(f"Target: {self.target}")
        print(f"Safety Delay: {self.delay}s")
        print(f"{'='*60}\n")
        
        # Test 1: CSRF token presence
        print("🎫 Test 1: CSRF Token Presence")
        self._test_token_presence()
        time.sleep(self.delay)
        
        # Test 2: Token validation
        print("\n✅ Test 2: Token Validation")
        self._test_token_validation()
        time.sleep(self.delay)
        
        # Test 3: SameSite cookies
        print("\n🍪 Test 3: SameSite Cookie Protection")
        self._test_samesite_cookies()
        time.sleep(self.delay)
        
        # Test 4: Referer validation
        print("\n🔗 Test 4: Referer Validation")
        self._test_referer_validation()
        
        # Save results
        self._save_results()
        
        print(f"\n{'='*60}")
        print(f"✅ Scan Complete")
        print(f"Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"Requests: {self.request_count}/{self.max_requests}")
        print(f"{'='*60}\n")
        
        return self.vulnerabilities

    def _test_token_presence(self):
        """Test CSRF token presence in forms"""
        print("   Checking for CSRF tokens...")
        
        response = self._make_request(self.target)
        if not response:
            print("   ⚠️  Could not retrieve page")
            return
        
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            if not forms:
                print("   ℹ️  No forms found")
                return

            token_names = ['csrf', 'token', '_token', 'authenticity_token', 'csrf_token', 'xsrf', 'nonce']

            # A token may live outside the form (meta tag read by JS, or a
            # framework default). Detect those so we do not over-report.
            page_text = response.text.lower()
            has_meta_token = bool(soup.find('meta', attrs={'name': re.compile(r'csrf|xsrf', re.I)}))
            # SameSite cookies mitigate most CSRF even without a form token.
            samesite_cookie = any(
                c.has_nonstandard_attr('SameSite') for c in response.cookies
            )

            vulnerable_forms = []
            for i, form in enumerate(forms):
                method = form.get('method', 'GET').upper()
                if method != 'POST':
                    continue
                csrf_token = None
                for input_field in form.find_all('input'):
                    field_name = input_field.get('name', '').lower()
                    if any(token in field_name for token in token_names):
                        csrf_token = input_field.get('value')
                        break
                if not csrf_token:
                    vulnerable_forms.append({
                        'form_index': i,
                        'action': form.get('action', 'N/A'),
                        'method': method
                    })

            if vulnerable_forms:
                # Lower severity and flag for verification when a page-level token
                # or SameSite protection is present, since the form may still be
                # protected by a mechanism we cannot see in static HTML.
                mitigated = has_meta_token or samesite_cookie
                vuln = {
                    'type': 'CSRF - Possible Missing Token',
                    'severity': 'medium' if mitigated else 'high',
                    'confidence': 'needs-manual-verification',
                    'url': self.target,
                    'vulnerable_forms': vulnerable_forms,
                    'description': (f'{len(vulnerable_forms)} POST form(s) with no CSRF '
                                    f'token field. '
                                    + ('A page-level CSRF meta tag and/or SameSite '
                                       'cookie was also detected, which may already '
                                       'mitigate CSRF - verify enforcement manually.'
                                       if mitigated else
                                       'No page-level token or SameSite cookie detected.')),
                    'poc': f"<html><body><form id='csrf' action='{self.target}' method='POST'>...</form></body></html>",
                    'remediation': ['Add CSRF tokens to all state-changing forms',
                                    'Set SameSite=Lax/Strict on session cookies',
                                    'Validate the token server-side'],
                    'tags': ['csrf', 'missing_token', 'unconfirmed']
                }
                self.vulnerabilities.append(vuln)
                print(f"   ? {len(vulnerable_forms)} POST form(s) without a token field "
                      f"(mitigated={mitigated})")
            else:
                print("   ✓ All POST forms carry a token field")
        except Exception as e:
            print(f"   ⚠️  Error parsing HTML: {e}")

    def _test_token_validation(self):
        """Whether a CSRF token is actually enforced can only be proven by
        submitting a state-changing request with a missing/forged token and
        observing that it still succeeds - which requires an authenticated
        session and a known action endpoint. This previously appended a
        fabricated 'critical' for every target. Recorded as a manual check."""
        print("   Token enforcement requires a live action -> manual check")
        self.manual_checks.append({
            'type': 'CSRF - Token Enforcement',
            'severity': 'info',
            'confidence': 'manual-verification-required',
            'url': self.target,
            'how_to_confirm': ('Authenticate, then replay a state-changing POST '
                               'with the CSRF token removed and again with a forged '
                               'token. If the action still succeeds, the token is '
                               'not enforced (CSRF).'),
            'tags': ['csrf', 'validation', 'manual', 'unconfirmed']
        })

    def _test_samesite_cookies(self):
        """Test SameSite cookie protection"""
        print("   Analyzing SameSite cookies...")
        response = self._make_request(self.target)
        if response and response.cookies:
            missing_samesite = [c.name for c in response.cookies if not c.has_nonstandard_attr('SameSite')]
            if missing_samesite:
                vuln = {
                    'type': 'CSRF - Missing SameSite Cookies',
                    'severity': 'medium',
                    'url': self.target,
                    'cookies': missing_samesite,
                    'description': 'Cookies lack SameSite attribute',
                    'tags': ['csrf', 'samesite', 'cookies']
                }
                self.vulnerabilities.append(vuln)
                print(f"   ✓ Issue: {len(missing_samesite)} cookies without SameSite")
            else:
                print("   ✓ SameSite properly configured")

    def _test_referer_validation(self):
        """Referer validation only matters for state-changing requests, and a
        GET to the target returning 200 with an arbitrary Referer is completely
        normal - it is NOT evidence of a CSRF flaw. The old check flagged almost
        every site. Recorded as a manual check to run against a real action."""
        print("   Referer validation is action-specific -> manual check")
        self.manual_checks.append({
            'type': 'CSRF - Referer/Origin Validation',
            'severity': 'info',
            'confidence': 'manual-verification-required',
            'url': self.target,
            'how_to_confirm': ('Send a state-changing request (POST/PUT/DELETE) '
                               'to a real action endpoint with a foreign or absent '
                               'Referer/Origin header. If it still succeeds and no '
                               'CSRF token is enforced, it may be CSRF-able.'),
            'tags': ['csrf', 'referer', 'manual', 'unconfirmed']
        })

    def _make_request(self, url: str, headers: Dict = None) -> Optional[requests.Response]:
        if self.request_count >= self.max_requests: return None
        try:
            req_headers = headers if headers else self.headers
            response = requests.get(url, headers=req_headers, timeout=self.timeout, verify=False)
            self.request_count += 1
            return response
        except: return None

    def _save_results(self):
        output_dir = self.workspace / "csrf_tests"
        output_dir.mkdir(parents=True, exist_ok=True)
        safe_target = re.sub(r'[^\w\-]', '_', self.target)
        output_file = output_dir / f"{safe_target}_csrf.json"
        with open(output_file, 'w') as f:
            json.dump({'scanner': 'CSRFTester', 'target': self.target, 'vulnerabilities': self.vulnerabilities, 'manual_checks': self.manual_checks}, f, indent=2)
        print(f"\n💾 Saved: {output_file}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python csrf_tester.py <target_url>")
        sys.exit(1)
    scanner = CSRFTester(sys.argv[1], Path("revuex_workspace"), delay=5.0)
    scanner.scan()
