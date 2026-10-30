#!/usr/bin/env python3
"""
REVUEX - SSTI Engine
Detects and identifies Server-Side Template Injection
"""

import json
import time
from pathlib import Path
from core.base_scanner import BaseScanner

class SSTIEngine(BaseScanner):
    """
    SSTI Engine implementation using BaseScanner methods.
    """

    def __init__(self, target, workspace, delay=2.0):
        super().__init__(target, workspace, delay)
        self.payload_file = Path("payloads/ssti_payloads.json")

    def _load_vectors(self):
        """Loads vectors from your payloads/ folder"""
        try:
            with open(self.payload_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Could not load payloads: {e}")
            return {"polyglots": ["{{7*7}}", "${7*7}"], "engines": {}}

    def scan(self):
        """Main scanning logic called by launcher.

        False-positive fix: the old discovery looked for "49" (from {{7*7}}) in
        the response. "49" appears on countless pages by chance (prices, years,
        pixel sizes), and the check also fired when the template engine simply
        reflected the literal "{{7*7}}" without evaluating it. We now:
          1. use an arithmetic result that is extremely unlikely to occur by
             chance (1733*1733 = 3003289), and
          2. require that the computed result appears while the RAW payload does
             NOT - i.e. the expression was actually evaluated, not echoed.
        """
        self.logger.info(f"Scanning {self.target} for SSTI...")

        # Deterministic, high-entropy arithmetic probe.
        a, b = 1733, 1733
        expected = str(a * b)  # 3003289
        probes = [
            ("{{%d*%d}}" % (a, b), "{{...}}"),
            ("${%d*%d}" % (a, b), "${...}"),
            ("#{%d*%d}" % (a, b), "#{...}"),
            ("*{%d*%d}" % (a, b), "*{...}"),
        ]

        # Baseline so we don't credit a page that already contains the number.
        base = self.safe_request("GET", self.target, params={"q": "revuex_ssti_probe"})
        base_text = base.text if base else ""

        for raw_payload, syntax in probes:
            response = self.safe_request("GET", self.target, params={"q": raw_payload})
            if not response:
                continue
            body = response.text
            evaluated = (expected in body) and (expected not in base_text)
            reflected_literally = raw_payload in body
            if evaluated and not reflected_literally:
                self.logger.info(f"SSTI evaluation confirmed with: {raw_payload}")
                self._identify_engine(vectors=self._load_vectors().get("engines", {}),
                                      discovery_payload=raw_payload,
                                      expected=expected, syntax=syntax)
                break

        return self.vulnerabilities

    def _identify_engine(self, engines, discovery_payload, expected, syntax="{{...}}"):
        """Identification Phase"""
        found_name = "Generic/Unknown"

        for name, payload in engines.items():
            response = self.safe_request("GET", self.target, params={"q": payload})
            if response and self._check_fingerprint(name, response.text):
                found_name = name
                break

        # Use your BaseScanner's add_vulnerability method
        self.add_vulnerability({
            "type": f"SSTI - {found_name}",
            "severity": "critical",
            "url": self.target,
            "description": f"Server-Side Template Injection detected ({found_name}).",
            "evidence": (f"Payload {discovery_payload} ({syntax}) was evaluated: the "
                         f"response contained the computed value '{expected}' while "
                         f"the raw expression was not reflected verbatim."),
            "remediation": "Never concatenate user input directly into templates. Use static templates with variables passed as arguments."
        })

    def _check_fingerprint(self, name, body):
        """Simple fingerprints for major engines"""
        fingerprints = {
            "Jinja2": "dict_items", 
            "Twig": "Twig_Environment",
            "Mako": "mako.runtime",
            "Smarty": "Smarty_Internal"
        }
        return fingerprints.get(name, "!!!") in body
