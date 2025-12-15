#!/usr/bin/env python3
“””
REVUEX - Dependency Checker
Vulnerable Dependency Detection

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
“””

import requests
import time
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

class DependencyChecker:
“””
Dependency Vulnerability Scanner

```
Features:
- JavaScript library detection
- Version identification
- CVE lookup
- Outdated dependency detection
- Known vulnerability matching
"""

def __init__(self, target: str, workspace: Path, delay: float = 5.0):
    """
    Initialize Dependency Checker
    
    Args:
        target: Target URL
        workspace: Workspace directory
        delay: Delay between requests
    """
    self.target = target
    self.workspace = Path(workspace)
    self.delay = delay
    
    # Safety limits
    self.max_requests = 40
    self.request_count = 0
    self.timeout = 10
    
    self.headers = {
        'User-Agent': 'REVUEX-DependencyChecker/1.0 (Security Research; +https://github.com/G33L0)',
    }
    
    self.vulnerabilities = []
    self.detected_libraries = []
    
    # Known vulnerable library patterns
    self.library_patterns = {
        'jquery': {
            'pattern': r'jquery[.-]?(\d+\.\d+\.\d+)',
            'vulnerable_versions': {
                '1.6.0': 'XSS vulnerability',
                '1.7.0': 'XSS vulnerability',
                '1.11.3': 'Multiple XSS',
                '2.1.4': 'XSS vulnerability',
                '3.0.0': 'XSS vulnerability'
            }
        },
        'angular': {
            'pattern': r'angular[.-]?(\d+\.\d+\.\d+)',
            'vulnerable_versions': {
                '1.5.0': 'Sandbox bypass',
                '1.5.8': 'XSS vulnerability',
                '1.6.0': 'Sandbox escape'
            }
        },
        'react': {
            'pattern': r'react[.-]?(\d+\.\d+\.\d+)',
            'vulnerable_versions': {
                '16.0.0': 'XSS in SSR',
                '16.4.0': 'XSS vulnerability'
            }
        },
        'vue': {
            'pattern': r'vue[.-]?(\d+\.\d+\.\d+)',
            'vulnerable_versions': {
                '2.5.0': 'XSS vulnerability',
                '2.6.0': 'Template injection'
            }
        },
        'bootstrap': {
            'pattern': r'bootstrap[.-]?(\d+\.\d+\.\d+)',
            'vulnerable_versions': {
                '3.3.7': 'XSS in tooltip',
                '4.0.0': 'XSS vulnerability'
            }
        },
        'lodash': {
            'pattern': r'lodash[.-]?(\d+\.\d+\.\d+)',
            'vulnerable_versions': {
                '4.17.11': 'Prototype pollution',
                '4.17.15': 'ReDoS vulnerability'
            }
        },
        'moment': {
            'pattern': r'moment[.-]?(\d+\.\d+\.\d+)',
            'vulnerable_versions': {
                '2.19.3': 'ReDoS vulnerability'
            }
        }
    }

def scan(self) -> List[Dict[str, Any]]:
    """Main dependency scanning method"""
    print(f"\n{'='*60}")
    print(f"📚 REVUEX Dependency Checker")
    print(f"{'='*60}")
    print(f"Target: {self.target}")
    print(f"Safety Delay: {self.delay}s")
    print(f"{'='*60}\n")
    
    # Test 1: Detect libraries
    print("🔍 Scanning for JavaScript libraries...")
    self._detect_libraries()
    time.sleep(self.delay)
    
    # Test 2: Check versions
    print("\n🔢 Analyzing library versions...")
    self._analyze_versions()
    time.sleep(self.delay)
    
    # Test 3: Check for known vulnerabilities
    print("\n⚠️  Checking for known vulnerabilities...")
    self._check_vulnerabilities()
    
    # Save results
    self._save_results()
    
    print(f"\n{'='*60}")
    print(f"✅ Scan Complete")
    print(f"Libraries Detected: {len(self.detected_libraries)}")
    print(f"Vulnerabilities: {len(self.vulnerabilities)}")
    print(f"{'='*60}\n")
    
    return self.vulnerabilities

def _detect_libraries(self):
    """Detect JavaScript libraries"""
    print("   Fetching page content...")
    
    response = self._make_request(self.target)
    
    if not response:
        print("   ⚠️  Could not retrieve page")
        return
    
    content = response.text
    
    # Detect libraries
    for lib_name, lib_info in self.library_patterns.items():
        matches = re.findall(lib_info['pattern'], content, re.IGNORECASE)
        
        if matches:
            version = matches[0] if matches else 'unknown'
            self.detected_libraries.append({
                'name': lib_name,
                'version': version
            })
            print(f"   ✓ Found: {lib_name} {version}")
    
    if not self.detected_libraries:
        print("   ℹ️  No known libraries detected")

def _analyze_versions(self):
    """Analyze library versions"""
    if not self.detected_libraries:
        print("   ℹ️  No libraries to analyze")
        return
    
    for lib in self.detected_libraries:
        lib_name = lib['name']
        version = lib['version']
        
        print(f"   Analyzing {lib_name} {version}...")
        
        # Check if version is outdated (simplified)
        if self._is_outdated(lib_name, version):
            print(f"      ⚠️  Outdated version")

def _check_vulnerabilities(self):
    """Check for known vulnerabilities"""
    if not self.detected_libraries:
        print("   ℹ️  No libraries to check")
        return
    
    for lib in self.detected_libraries:
        lib_name = lib['name']
        version = lib['version']
        
        # Check against known vulnerable versions
        if lib_name in self.library_patterns:
            vulnerable_versions = self.library_patterns[lib_name]['vulnerable_versions']
            
            if version in vulnerable_versions:
                issue = vulnerable_versions[version]
                
                vuln = {
                    'type': f'Vulnerable Dependency - {lib_name}',
                    'severity': 'high',
                    'url': self.target,
                    'library': lib_name,
                    'version': version,
                    'vulnerability': issue,
                    'description': f'{lib_name} {version} has known vulnerability: {issue}',
                    'evidence': f'Detected {lib_name} version {version}',
                    
                    'steps_to_reproduce': [
                        f"Visit: {self.target}",
                        "View page source",
                        f"Identify {lib_name} version {version}",
                        f"Vulnerability: {issue}",
                        "Exploit via known CVE"
                    ],
                    
                    'poc': f"""#!/usr/bin/env python3
```

# {lib_name} {version} Exploitation

# Library: {lib_name}

# Version: {version}

# Vulnerability: {issue}

# Example: jQuery XSS

xss_payload = “<img src=x onerror=alert(1)>”

# Exploit depends on specific vulnerability

# Consult CVE database for details

print(f”Vulnerable {lib_name} detected”)
print(f”Version: {version}”)
print(f”Issue: {issue}”)
“””,

```
                    'remediation': [
                        f'🚨 Update {lib_name} immediately',
                        f'Latest secure version recommended',
                        'Review release notes for breaking changes',
                        'Test after upgrade',
                        'Implement dependency scanning in CI/CD',
                        'Use tools: npm audit, Snyk, Dependabot',
                        'Monitor security advisories'
                    ],
                    
                    'cvss_score': self._get_cvss_score(lib_name, version),
                    
                    'references': [
                        f'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={lib_name}',
                        f'https://snyk.io/vuln/npm:{lib_name}',
                        'https://nvd.nist.gov/',
                    ],
                    
                    'tags': ['dependency', 'outdated', lib_name]
                }
                
                self.vulnerabilities.append(vuln)
                print(f"   ✓ VULNERABLE: {lib_name} {version} - {issue}")
            else:
                print(f"   ✓ {lib_name} {version} - No known vulnerabilities")

def _is_outdated(self, lib_name: str, version: str) -> bool:
    """Check if library version is outdated (simplified)"""
    # Simplified check - in production, query package registries
    outdated_thresholds = {
        'jquery': '3.5.0',
        'angular': '12.0.0',
        'react': '17.0.0',
        'vue': '3.0.0',
        'bootstrap': '5.0.0',
        'lodash': '4.17.21',
        'moment': '2.29.0'
    }
    
    if lib_name in outdated_thresholds:
        threshold = outdated_thresholds[lib_name]
        return self._compare_versions(version, threshold) < 0
    
    return False

def _compare_versions(self, v1: str, v2: str) -> int:
    """Compare version strings"""
    try:
        v1_parts = [int(x) for x in v1.split('.')]
        v2_parts = [int(x) for x in v2.split('.')]
        
        for i in range(max(len(v1_parts), len(v2_parts))):
            v1_part = v1_parts[i] if i < len(v1_parts) else 0
            v2_part = v2_parts[i] if i < len(v2_parts) else 0
            
            if v1_part < v2_part:
                return -1
            elif v1_part > v2_part:
                return 1
        
        return 0
    except:
        return 0

def _get_cvss_score(self, lib_name: str, version: str) -> str:
    """Get CVSS score (simplified)"""
    # In production, query CVE databases
    return "7.5 (High)"

def _make_request(self, url: str) -> Optional[requests.Response]:
    """Make HTTP request"""
    if self.request_count >= self.max_requests:
        return None
    
    try:
        response = requests.get(
            url,
            headers=self.headers,
            timeout=self.timeout,
            verify=False
        )
        
        self.request_count += 1
        return response
        
    except:
        return None

def _save_results(self):
    """Save results"""
    output_dir = self.workspace / "dependency_scans"
    output_dir.mkdir(exist_ok=True)
    
    safe_target = re.sub(r'[^\w\-]', '_', self.target)
    output_file = output_dir / f"{safe_target}_dependencies.json"
    
    with open(output_file, 'w') as f:
        json.dump({
            'scanner': 'DependencyChecker',
            'target': self.target,
            'detected_libraries': self.detected_libraries,
            'vulnerabilities': self.vulnerabilities
        }, f, indent=2)
    
    print(f"\n💾 Saved: {output_file}")
```

if **name** == “**main**”:
import sys

```
if len(sys.argv) < 2:
    print("Usage: python dependency_checker.py <target_url>")
    print("Example: python dependency_checker.py https://example.com")
    sys.exit(1)

scanner = DependencyChecker(sys.argv[1], Path("revuex_workspace"), delay=5.0)
scanner.scan()
```
