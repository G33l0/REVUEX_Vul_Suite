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
        """Main scanning logic called by launcher"""
        self.logger.info(f"Scanning {self.target} for SSTI...")
        vectors = self._load_vectors()
        
        # 1. Discovery Phase
        for polyglot in vectors.get("polyglots", []):
            # Use your BaseScanner's safe_request method
            response = self.safe_request("GET", self.target, params={"q": polyglot})
            
            if response and "49" in response.text:
                self.logger.info(f"Potential SSTI found with: {polyglot}")
                self._identify_engine(vectors.get("engines", {}), polyglot)
                break
        
        return self.vulnerabilities

    def _identify_engine(self, engines, discovery_payload):
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
            "evidence": f"Payload: {discovery_payload} rendered '49' in response.",
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
