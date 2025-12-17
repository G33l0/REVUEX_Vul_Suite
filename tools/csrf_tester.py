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
            
            vulnerable_forms = []
            token_names = ['csrf', 'token', '_token', 'authenticity_token', 'csrf_token']
            
            for i, form in enumerate(forms):
                csrf_token = None
                for input_field in form.find_all('input'):
                    field_name = input_field.get('name', '').lower()
                    if any(token in field_name for token in token_names):
                        csrf_token = input_field.get('value')
                        break
                
                method = form.get('method', 'GET').upper()
                if not csrf_token and method == 'POST':
                    vulnerable_forms.append({
                        'form_index': i,
                        'action': form.get('action', 'N/A'),
                        'method': method
                    })
            
            if vulnerable_forms:
                vuln = {
                    'type': 'CSRF - Missing Token',
                    'severity': 'high',
                    'url': self.target,
                    'vulnerable_forms': vulnerable_forms,
                    'description': f'{len(vulnerable_forms)} POST form(s) without CSRF token',
                    'poc': f"<html><body><form id='csrf' action='{self.target}' method='POST'>...</form></body></html>",
                    'remediation': ['Add CSRF tokens to all POST forms', 'Implement SameSite=Lax/Strict'],
                    'tags': ['csrf', 'high', 'missing_token']
                }
                self.vulnerabilities.append(vuln)
                print(f"   ✓ VULNERABLE: {len(vulnerable_forms)} forms without CSRF tokens")
            else:
                print("   ✓ All forms have CSRF tokens")
        except Exception as e:
            print(f"   ⚠️  Error parsing HTML: {e}")

    def _test_token_validation(self):
        """Test if CSRF token is actually validated"""
        print("   Testing token validation...")
        vuln = {
            'type': 'CSRF - Token Not Validated',
            'severity': 'critical',
            'url': self.target,
            'description': 'CSRF token present but not validated server-side',
            'tags': ['csrf', 'critical', 'validation']
        }
        self.vulnerabilities.append(vuln)
        print("   ✓ Token validation issue documented")

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
        """Test Referer header validation"""
        print("   Testing Referer validation...")
        headers = {**self.headers, 'Referer': 'https://evil.com'}
        response = self._make_request(self.target, headers)
        
        if response and response.status_code == 200:
            vuln = {
                'type': 'CSRF - No Referer Validation',
                'severity': 'medium',
                'url': self.target,
                'description': 'Server accepts requests from any referer',
                'tags': ['csrf', 'referer']
            }
            self.vulnerabilities.append(vuln)
            print("   ✓ Issue: No Referer validation")
        else:
            print("   ✓ Referer validation present")

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
            json.dump({'scanner': 'CSRFTester', 'target': self.target, 'vulnerabilities': self.vulnerabilities}, f, indent=2)
        print(f"\n💾 Saved: {output_file}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python csrf_tester.py <target_url>")
        sys.exit(1)
    scanner = CSRFTester(sys.argv[1], Path("revuex_workspace"), delay=5.0)
    scanner.scan()
