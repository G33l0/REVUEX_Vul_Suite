#!/usr/bin/env python3
"""
REVUEX - IDOR Tester
Insecure Direct Object Reference Detection & Exploitation

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
IDOR testing can expose private data - use only on systems you own or have permission to test.
"""

import requests
import time
import json
import re
import base64
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import uuid


class IDORTester:
    """
    Advanced IDOR (Insecure Direct Object Reference) Tester

    Features:
    - Sequential numeric ID enumeration
    - UUID/GUID pattern analysis
    - Base64-encoded ID testing
    - Hash-based identifier prediction
    - Horizontal privilege escalation detection
    - Vertical privilege escalation detection
    - Smart pattern recognition
    - Authorization bypass techniques
    - Bulk enumeration capabilities
    """

    def __init__(self, target: str, workspace: Path, delay: float = 5.0):
        self.target = target
        self.workspace = Path(workspace)
        self.delay = delay

        self.max_requests = 100
        self.request_count = 0
        self.timeout = 10

        self.headers = {
            "User-Agent": "REVUEX-IDORTester/1.0 (Security Research; +https://github.com/G33L0)",
            "Accept": "application/json, text/html, */*"
        }

        self.vulnerabilities: List[Dict[str, Any]] = []
        self.baseline_responses: Dict[str, str] = {}

    # =========================
    # MAIN SCAN
    # =========================

    def scan(self) -> List[Dict[str, Any]]:
        print("\n" + "=" * 60)
        print("🔐 REVUEX IDOR Tester")
        print("=" * 60)
        print(f"Target: {self.target}")
        print(f"Safety Delay: {self.delay}s")
        print(f"Max Requests: {self.max_requests}")
        print("=" * 60 + "\n")

        print("🔍 Step 1: Identifying ID Parameters")
        id_params = self._identify_id_parameters()
        if not id_params:
            print("⚠️ No ID parameters detected.")
            return []

        print("\n📊 Step 2: Analyzing ID Pattern")
        pattern = self._analyze_id_pattern(id_params)

        if pattern["type"] == "numeric":
            print("\n🔢 Step 3: Sequential Numeric ID Testing")
            self._test_sequential_numeric(id_params)

        if pattern["type"] == "uuid":
            print("\n🆔 Step 4: UUID Testing")
            self._test_uuid_patterns(id_params)

        if pattern["type"] == "base64":
            print("\n📦 Step 5: Base64 ID Testing")
            self._test_base64_ids(id_params)

        if pattern["type"] == "hash":
            print("\n#️⃣ Step 6: Hash ID Testing")
            self._test_hash_ids(id_params)

        print("\n🔓 Step 7: Authorization Bypass Testing")
        self._test_authorization_bypass(id_params)

        self._save_results()

        print("\n" + "=" * 60)
        print("✅ Scan Complete")
        print(f"Vulnerabilities Found: {len(self.vulnerabilities)}")
        print(f"Requests Used: {self.request_count}/{self.max_requests}")
        print("=" * 60)

        return self.vulnerabilities

    # =========================
    # PARAMETER & PATTERN
    # =========================

    def _identify_id_parameters(self) -> Dict[str, str]:
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        found = {}

        for k, v in params.items():
            if v:
                found[k] = v[0]
                print(f"   ✓ Found parameter: {k}={v[0]}")

        return found

    def _analyze_id_pattern(self, id_params: Dict[str, str]) -> Dict[str, Any]:
        value = list(id_params.values())[0]

        if value.isdigit():
            return {"type": "numeric"}
        if self._is_uuid(value):
            return {"type": "uuid"}
        if self._is_base64(value):
            return {"type": "base64"}
        if self._is_hash(value):
            return {"type": "hash"}

        return {"type": "unknown"}

    # =========================
    # TESTS
    # =========================

    def _test_sequential_numeric(self, id_params: Dict[str, str]):
        param = list(id_params.keys())[0]
        original = int(id_params[param])

        baseline = self._make_request(param, str(original))
        if not baseline:
            return

        baseline_len = len(baseline.text)
        vulnerable = []

        for i in [original - 1, original + 1, 1, 2]:
            if i <= 0:
                continue
            resp = self._make_request(param, str(i))
            if resp and resp.status_code == 200:
                if abs(len(resp.text) - baseline_len) > 50:
                    vulnerable.append(i)

        if vulnerable:
            self.vulnerabilities.append(
                self._create_sequential_idor_vuln(param, original, vulnerable)
            )

    def _test_uuid_patterns(self, id_params: Dict[str, str]):
        param = list(id_params.keys())[0]
        vulnerable = []

        for _ in range(3):
            test_uuid = str(uuid.uuid4())
            resp = self._make_request(param, test_uuid)
            if resp and resp.status_code == 200:
                vulnerable.append(test_uuid)

        if vulnerable:
            self.vulnerabilities.append(
                self._create_uuid_idor_vuln(param, id_params[param], vulnerable)
            )

    def _test_base64_ids(self, id_params: Dict[str, str]):
        param = list(id_params.keys())[0]
        original = id_params[param]

        try:
            decoded = base64.b64decode(original).decode()
        except Exception:
            return

        vulnerable = []
        if decoded.isdigit():
            for i in [1, 2, int(decoded) + 1]:
                enc = base64.b64encode(str(i).encode()).decode()
                resp = self._make_request(param, enc)
                if resp and resp.status_code == 200:
                    vulnerable.append(enc)

        if vulnerable:
            self.vulnerabilities.append(
                self._create_base64_idor_vuln(param, original, vulnerable)
            )

    def _test_hash_ids(self, id_params: Dict[str, str]):
        param = list(id_params.keys())[0]
        vulnerable = []

        for val in ["admin", "user", "1"]:
            h = hashlib.md5(val.encode()).hexdigest()
            resp = self._make_request(param, h)
            if resp and resp.status_code == 200:
                vulnerable.append(h)

        if vulnerable:
            self.vulnerabilities.append(
                self._create_hash_idor_vuln(param, id_params[param], vulnerable)
            )

    def _test_authorization_bypass(self, id_params: Dict[str, str]):
        param = list(id_params.keys())[0]
        original = id_params[param]
        vulnerable = []

        for payload in [f"{original}&{param}=1", f"{original}[]", f"{original}%00"]:
            resp = self._make_request(param, payload)
            if resp and resp.status_code == 200:
                vulnerable.append(payload)

        if vulnerable:
            self.vulnerabilities.append(
                self._create_bypass_vuln(param, original, vulnerable)
            )

    # =========================
    # VULNERABILITY BUILDERS
    # =========================

    def _create_sequential_idor_vuln(self, param, original, ids):
        return {
            "type": "IDOR - Sequential Numeric IDs",
            "severity": "critical",
            "parameter": param,
            "original_id": original,
            "accessible_ids": ids,
            "description": "Sequential IDs allow unauthorized access",
            "impact": "PII exposure, account takeover",
            "remediation": [
                "Implement authorization checks",
                "Do not rely on ID secrecy",
                "Use UUIDs",
                "RBAC / ABAC enforcement"
            ],
            "tags": ["idor", "critical"]
        }

    def _create_uuid_idor_vuln(self, param, original, uuids):
        return {
            "type": "IDOR - UUID Enumeration",
            "severity": "high",
            "parameter": param,
            "uuids": uuids,
            "description": "UUIDs enumerated without authorization",
            "tags": ["idor", "uuid"]
        }

    def _create_base64_idor_vuln(self, param, original, ids):
        return {
            "type": "IDOR - Base64 Encoding Bypass",
            "severity": "critical",
            "parameter": param,
            "encoded_ids": ids,
            "description": "Base64 is reversible encoding",
            "tags": ["idor", "base64"]
        }

    def _create_hash_idor_vuln(self, param, original, hashes):
        return {
            "type": "IDOR - Predictable Hashes",
            "severity": "high",
            "parameter": param,
            "hashes": hashes,
            "tags": ["idor", "hash"]
        }

    def _create_bypass_vuln(self, param, original, payloads):
        return {
            "type": "IDOR - Authorization Bypass",
            "severity": "critical",
            "parameter": param,
            "payloads": payloads,
            "tags": ["idor", "bypass"]
        }

    # =========================
    # UTILS
    # =========================

    def _make_request(self, param, value) -> Optional[requests.Response]:
        if self.request_count >= self.max_requests:
            return None

        try:
            url = self._modify_url_param(self.target, param, value)
            resp = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False)
            self.request_count += 1
            time.sleep(self.delay)
            return resp
        except Exception:
            return None

    def _modify_url_param(self, url, param, value):
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        q[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(q, doseq=True)))

    def _is_uuid(self, v): return bool(re.match(r"^[0-9a-fA-F\-]{36}$", v))
    def _is_base64(self, v):
        try:
            base64.b64decode(v)
            return True
        except Exception:
            return False
    def _is_hash(self, v): return len(v) in [32, 40, 64]

    def _save_results(self):
        out = self.workspace / "idor_tests"
        out.mkdir(parents=True, exist_ok=True)
        name = re.sub(r"[^\w\-]", "_", self.target)
        with open(out / f"{name}_idor.json", "w") as f:
            json.dump(self.vulnerabilities, f, indent=2)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python idor_tester.py <target_url>")
        sys.exit(1)

    scanner = IDORTester(sys.argv[1], Path("revuex_workspace"))
    scanner.scan()