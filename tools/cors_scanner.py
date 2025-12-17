#!/usr/bin/env python3
"""
REVUEX - CORS Scanner
Cross-Origin Resource Sharing Misconfiguration Detection

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

# Suppress insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CORSScanner:
    """
    CORS Misconfiguration Scanner
    
    Features:
    - Wildcard origin with credentials
    - Null origin acceptance
    - Origin reflection testing
    - Subdomain wildcard detection
    - Pre-flight bypass testing
    - CORS with credentials
    """

    def __init__(self, target: str, workspace: Path, delay: float = 5.0):
        """
        Initialize CORS Scanner
        
        Args:
            target: Target URL
            workspace: Workspace directory
            delay: Delay between requests
        """
        self.target = target
        self.workspace = Path(workspace)
        self.delay = delay
        
        # Safety limits
        self.max_requests = 50
        self.request_count = 0
        self.timeout = 10
        
        self.headers = {
            'User-Agent': 'REVUEX-CORSScanner/1.0 (Security Research; +https://github.com/G33L0)',
        }
        
        self.vulnerabilities = []

    def scan(self) -> List[Dict[str, Any]]:
        """Main CORS scanning method"""
        print(f"\n{'='*60}")
        print(f"🌐 REVUEX CORS Scanner")
        print(f"{'='*60}")
        print(f"Target: {self.target}")
        print(f"Safety Delay: {self.delay}s")
        print(f"{'='*60}\n")
        
        # Test 1: Wildcard with credentials
        print("🔓 Test 1: Wildcard Origin + Credentials")
        self._test_wildcard_credentials()
        time.sleep(self.delay)
        
        # Test 2: Null origin
        print("\n⚫ Test 2: Null Origin")
        self._test_null_origin()
        time.sleep(self.delay)
        
        # Test 3: Origin reflection
        print("\n🪞 Test 3: Origin Reflection")
        self._test_origin_reflection()
        time.sleep(self.delay)
        
        # Test 4: Subdomain wildcard
        print("\n🌳 Test 4: Subdomain Wildcard")
        self._test_subdomain_wildcard()
        
        # Save results
        self._save_results()
        
        print(f"\n{'='*60}")
        print(f"✅ Scan Complete")
        print(f"Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"Requests: {self.request_count}/{self.max_requests}")
        print(f"{'='*60}\n")
        
        return self.vulnerabilities

    def _test_wildcard_credentials(self):
        """Test wildcard origin with credentials"""
        print("   Testing wildcard configuration...")
        
        test_origin = "https://evil.com"
        headers = {**self.headers, 'Origin': test_origin}
        response = self._make_request(self.target, headers)
        
        if response:
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == '*' and acac.lower() == 'true':
                vuln = {
                    'type': 'CORS - Wildcard with Credentials',
                    'severity': 'critical',
                    'url': self.target,
                    'description': 'CORS configured with wildcard (*) origin AND credentials enabled',
                    'evidence': f'Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true',
                    'steps_to_reproduce': [
                        f"Send request to: {self.target}",
                        f"Include header: Origin: {test_origin}",
                        "Server responds with Access-Control-Allow-Credentials: true"
                    ],
                    'poc': f"fetch('{self.target}', {{credentials: 'include'}}).then(r => r.json()).then(console.log);",
                    'remediation': [
                        '🚨 CRITICAL: Never use * with credentials',
                        'Use specific allowed origins',
                        'Validate Origin header server-side'
                    ],
                    'tags': ['cors', 'critical', 'wildcard']
                }
                self.vulnerabilities.append(vuln)
                print("   ✓ VULNERABLE: Wildcard + Credentials")
            else:
                print("   ✓ Protected: No wildcard with credentials")

    def _test_null_origin(self):
        """Test null origin acceptance"""
        print("   Testing null origin...")
        
        headers = {**self.headers, 'Origin': 'null'}
        response = self._make_request(self.target, headers)
        
        if response:
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == 'null' and acac.lower() == 'true':
                vuln = {
                    'type': 'CORS - Null Origin Accepted',
                    'severity': 'high',
                    'url': self.target,
                    'description': 'Server accepts "null" origin with credentials',
                    'poc': '<iframe sandbox="allow-scripts" srcdoc="<script>fetch(...)"></iframe>',
                    'remediation': ['Never allow "null" origin', 'Reject null explicitly'],
                    'tags': ['cors', 'null_origin']
                }
                self.vulnerabilities.append(vuln)
                print("   ✓ VULNERABLE: Null origin accepted")
            else:
                print("   ✓ Protected: Null origin rejected")

    def _test_origin_reflection(self):
        """Test origin reflection"""
        print("   Testing origin reflection...")
        test_origins = ['https://evil.com', 'https://attacker.co', 'https://malicious.org']
        
        for test_origin in test_origins:
            headers = {**self.headers, 'Origin': test_origin}
            response = self._make_request(self.target, headers)
            
            if response:
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao == test_origin and acac.lower() == 'true':
                    vuln = {
                        'type': 'CORS - Origin Reflection',
                        'severity': 'critical',
                        'url': self.target,
                        'reflected_origin': test_origin,
                        'description': 'Server reflects arbitrary Origin header with credentials',
                        'remediation': ['Implement origin whitelist', 'Never reflect untrusted origins'],
                        'tags': ['cors', 'critical', 'reflection']
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"   ✓ VULNERABLE: Reflects {test_origin}")
                    break
            time.sleep(self.delay)
        else:
            print("   ✓ Protected: No origin reflection")

    def _test_subdomain_wildcard(self):
        """Test subdomain wildcard"""
        print("   Testing subdomain wildcard...")
        parsed = urlparse(self.target)
        domain = parsed.netloc
        test_subdomains = [f'https://evil.{domain}', f'https://attacker.{domain}']
        
        for subdomain in test_subdomains:
            headers = {**self.headers, 'Origin': subdomain}
            response = self._make_request(self.target, headers)
            if response:
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                if subdomain in acao:
                    vuln = {
                        'type': 'CORS - Subdomain Wildcard',
                        'severity': 'medium',
                        'url': self.target,
                        'description': 'Subdomain wildcard allows any subdomain',
                        'tags': ['cors', 'subdomain']
                    }
                    self.vulnerabilities.append(vuln)
                    print("   ✓ Issue: Subdomain wildcard detected")
                    break
            time.sleep(self.delay)
        else:
            print("   ✓ No subdomain wildcard")

    def _make_request(self, url: str, headers: Dict) -> Optional[requests.Response]:
        """Make HTTP request"""
        if self.request_count >= self.max_requests:
            return None
        try:
            response = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
            self.request_count += 1
            return response
        except:
            return None

    def _save_results(self):
        """Save results"""
        output_dir = self.workspace / "cors_scans"
        output_dir.mkdir(exist_ok=True, parents=True)
        safe_target = re.sub(r'[^\w\-]', '_', self.target)
        output_file = output_dir / f"{safe_target}_cors.json"
        with open(output_file, 'w') as f:
            json.dump({
                'scanner': 'CORSScanner',
                'target': self.target,
                'vulnerabilities': self.vulnerabilities
            }, f, indent=2)
        print(f"\n💾 Saved: {output_file}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python cors_scanner.py <target_url>")
        sys.exit(1)
    scanner = CORSScanner(sys.argv[1], Path("revuex_workspace"), delay=5.0)
    scanner.scan()
