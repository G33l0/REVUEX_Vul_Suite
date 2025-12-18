#!/usr/bin/env python3
"""
REVUEX - Enhanced IDOR Hunter v2.0
Two-Account Access Control Testing Framework

Advanced IDOR detection using dual-account verification to prove
actual access control violations rather than simple ID enumeration.

Author: G33L0 (@x0x0h33l0)
Part of REVUEX Bug Bounty Automation Framework
"""

import requests
import json
import argparse
import time
import re
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import sys

# Color codes for output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

@dataclass
class AccountCredentials:
    """Store account credentials and session data"""
    name: str
    auth_header: Dict[str, str]
    cookies: Dict[str, str]
    user_id: Optional[str] = None
    resources: List[str] = None
    
    def __post_init__(self):
        if self.resources is None:
            self.resources = []

@dataclass
class IDORVulnerability:
    """Store details of confirmed IDOR vulnerability"""
    endpoint: str
    method: str
    resource_id: str
    owner_account: str
    attacker_account: str
    vulnerability_type: str  # read, write, delete
    response_code: int
    leaked_data: str
    severity: str
    timestamp: str

class IDORHunter:
    """Advanced IDOR detection with two-account verification"""
    
    def __init__(self, base_url: str, account_a: AccountCredentials, 
                 account_b: AccountCredentials, delay: float = 1.0):
        self.base_url = base_url.rstrip('/')
        self.account_a = account_a
        self.account_b = account_b
        self.delay = delay
        self.vulnerabilities: List[IDORVulnerability] = []
        self.session = requests.Session()
        self.request_count = 0
        
        # Common IDOR endpoints patterns
        self.test_patterns = [
            "/api/user/{id}",
            "/api/users/{id}",
            "/api/profile/{id}",
            "/api/account/{id}",
            "/api/document/{id}",
            "/api/file/{id}",
            "/api/order/{id}",
            "/api/invoice/{id}",
            "/api/message/{id}",
            "/api/ticket/{id}",
            "/api/reservation/{id}",
            "/api/booking/{id}",
            "/api/payment/{id}",
            "/api/subscription/{id}",
            "/api/membership/{id}",
            "/api/settings/{id}",
            "/api/preferences/{id}",
            "/api/notifications/{id}",
            "/api/reports/{id}",
            "/api/analytics/{id}",
        ]
        
        # Sensitivity keywords for data classification
        self.sensitive_keywords = [
            'password', 'ssn', 'social', 'credit', 'card', 'cvv',
            'email', 'phone', 'address', 'salary', 'income',
            'medical', 'health', 'diagnosis', 'prescription',
            'account', 'balance', 'transaction', 'payment'
        ]
    
    def print_banner(self):
        """Display tool banner"""
        banner = f"""
{Colors.CYAN}ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
â              REVUEX - Enhanced IDOR Hunter v2.0                  â
â          Two-Account Access Control Verification                 â
ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ{Colors.ENDC}

{Colors.YELLOW}[*] Target:{Colors.ENDC} {self.base_url}
{Colors.YELLOW}[*] Account A:{Colors.ENDC} {self.account_a.name}
{Colors.YELLOW}[*] Account B:{Colors.ENDC} {self.account_b.name}
{Colors.YELLOW}[*] Test Mode:{Colors.ENDC} Two-Account Access Control Verification
{Colors.YELLOW}[*] Delay:{Colors.ENDC} {self.delay}s between requests
"""
        print(banner)
    
    def make_request(self, method: str, url: str, account: AccountCredentials,
                     data: Optional[Dict] = None, json_data: Optional[Dict] = None) -> requests.Response:
        """Make HTTP request with account credentials and safety measures"""
        self.request_count += 1
        
        headers = {
            'User-Agent': 'REVUEX-IDOR-Hunter/2.0',
            **account.auth_header
        }
        
        try:
            time.sleep(self.delay)
            
            if method.upper() == 'GET':
                response = self.session.get(url, headers=headers, cookies=account.cookies, timeout=10)
            elif method.upper() == 'POST':
                response = self.session.post(url, headers=headers, cookies=account.cookies, 
                                            data=data, json=json_data, timeout=10)
            elif method.upper() == 'PUT':
                response = self.session.put(url, headers=headers, cookies=account.cookies,
                                           data=data, json=json_data, timeout=10)
            elif method.upper() == 'PATCH':
                response = self.session.patch(url, headers=headers, cookies=account.cookies,
                                             data=data, json=json_data, timeout=10)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, headers=headers, cookies=account.cookies, timeout=10)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            return response
        
        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}[!] Request failed: {e}{Colors.ENDC}")
            return None
    
    def discover_user_id(self, account: AccountCredentials) -> Optional[str]:
        """Attempt to discover user ID for an account"""
        print(f"\n{Colors.CYAN}[*] Discovering user ID for {account.name}...{Colors.ENDC}")
        
        # Try common endpoints that reveal user ID
        id_endpoints = [
            '/api/me',
            '/api/user/me',
            '/api/profile',
            '/api/account',
            '/api/current-user',
            '/api/whoami',
            '/api/session',
        ]
        
        for endpoint in id_endpoints:
            url = urljoin(self.base_url, endpoint)
            response = self.make_request('GET', url, account)
            
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    # Look for common ID field names
                    for key in ['id', 'user_id', 'userId', 'uid', 'account_id', 'accountId']:
                        if key in data:
                            user_id = str(data[key])
                            print(f"{Colors.GREEN}[+] Found user ID: {user_id} (from {endpoint}){Colors.ENDC}")
                            return user_id
                    
                    # Try to extract from nested objects
                    if 'user' in data and isinstance(data['user'], dict):
                        for key in ['id', 'user_id', 'userId']:
                            if key in data['user']:
                                user_id = str(data['user'][key])
                                print(f"{Colors.GREEN}[+] Found user ID: {user_id} (from {endpoint}){Colors.ENDC}")
                                return user_id
                
                except json.JSONDecodeError:
                    continue
        
        print(f"{Colors.YELLOW}[!] Could not auto-discover user ID for {account.name}{Colors.ENDC}")
        return None
    
    def create_test_resource(self, account: AccountCredentials, endpoint: str) -> Optional[str]:
        """Create a test resource with Account A to later test access with Account B"""
        print(f"\n{Colors.CYAN}[*] Creating test resource with {account.name}...{Colors.ENDC}")
        
        # Common resource creation endpoints
        create_endpoints = [
            '/api/documents',
            '/api/files',
            '/api/notes',
            '/api/messages',
            '/api/posts',
            '/api/comments',
        ]
        
        test_data = {
            'title': f'IDOR Test Resource - {datetime.now().isoformat()}',
            'content': 'This is a test resource for IDOR testing',
            'name': 'IDOR Test',
            'description': 'Testing access control',
            'private': True,
            'sensitive': True
        }
        
        for create_endpoint in create_endpoints:
            url = urljoin(self.base_url, create_endpoint)
            response = self.make_request('POST', url, account, json_data=test_data)
            
            if response and response.status_code in [200, 201]:
                try:
                    data = response.json()
                    # Extract resource ID
                    for key in ['id', 'document_id', 'file_id', 'resource_id', 'uid']:
                        if key in data:
                            resource_id = str(data[key])
                            print(f"{Colors.GREEN}[+] Created resource: {resource_id}{Colors.ENDC}")
                            account.resources.append(resource_id)
                            return resource_id
                except json.JSONDecodeError:
                    # Try to extract ID from Location header
                    location = response.headers.get('Location', '')
                    id_match = re.search(r'/(\d+)$', location)
                    if id_match:
                        resource_id = id_match.group(1)
                        print(f"{Colors.GREEN}[+] Created resource: {resource_id} (from Location header){Colors.ENDC}")
                        account.resources.append(resource_id)
                        return resource_id
        
        return None
    
    def test_idor_read(self, endpoint_pattern: str, resource_id: str,
                       owner: AccountCredentials, attacker: AccountCredentials) -> Optional[IDORVulnerability]:
        """Test for read IDOR vulnerability"""
        endpoint = endpoint_pattern.format(id=resource_id)
        url = urljoin(self.base_url, endpoint)
        
        print(f"\n{Colors.CYAN}[*] Testing READ access: {endpoint}{Colors.ENDC}")
        
        # First, verify owner can access (baseline)
        owner_response = self.make_request('GET', url, owner)
        if not owner_response or owner_response.status_code != 200:
            print(f"{Colors.YELLOW}[!] Owner cannot access resource (skipping){Colors.ENDC}")
            return None
        
        owner_data = owner_response.text
        
        # Now test if attacker can access
        attacker_response = self.make_request('GET', url, attacker)
        
        if attacker_response and attacker_response.status_code == 200:
            attacker_data = attacker_response.text
            
            # Verify it's actually the same data
            if len(attacker_data) > 100 and attacker_data == owner_data:
                # Confirmed IDOR!
                severity = self._calculate_severity(attacker_data)
                leaked_preview = attacker_data[:200] if len(attacker_data) > 200 else attacker_data
                
                print(f"{Colors.RED}[!] IDOR VULNERABILITY FOUND!{Colors.ENDC}")
                print(f"{Colors.RED}    ââ Unauthorized read access to {owner.name}'s resource{Colors.ENDC}")
                
                vuln = IDORVulnerability(
                    endpoint=endpoint,
                    method='GET',
                    resource_id=resource_id,
                    owner_account=owner.name,
                    attacker_account=attacker.name,
                    vulnerability_type='read',
                    response_code=attacker_response.status_code,
                    leaked_data=leaked_preview,
                    severity=severity,
                    timestamp=datetime.now().isoformat()
                )
                
                self.vulnerabilities.append(vuln)
                return vuln
        
        print(f"{Colors.GREEN}[+] Access properly denied (status: {attacker_response.status_code if attacker_response else 'N/A'}){Colors.ENDC}")
        return None
    
    def test_idor_write(self, endpoint_pattern: str, resource_id: str,
                        owner: AccountCredentials, attacker: AccountCredentials) -> Optional[IDORVulnerability]:
        """Test for write/modify IDOR vulnerability"""
        endpoint = endpoint_pattern.format(id=resource_id)
        url = urljoin(self.base_url, endpoint)
        
        print(f"\n{Colors.CYAN}[*] Testing WRITE access: {endpoint}{Colors.ENDC}")
        
        # Prepare modification data
        modify_data = {
            'title': 'MODIFIED BY IDOR TEST',
            'content': 'This resource was modified via IDOR vulnerability',
            'modified': True
        }
        
        # Try to modify with attacker account
        for method in ['PUT', 'PATCH', 'POST']:
            attacker_response = self.make_request(method, url, attacker, json_data=modify_data)
            
            if attacker_response and attacker_response.status_code in [200, 201, 204]:
                # Verify modification by reading with owner account
                owner_response = self.make_request('GET', url, owner)
                
                if owner_response and owner_response.status_code == 200:
                    try:
                        data = owner_response.json()
                        if any(modify_data.get(k) == data.get(k) for k in modify_data.keys()):
                            # Confirmed write IDOR!
                            print(f"{Colors.RED}[!] WRITE IDOR VULNERABILITY FOUND!{Colors.ENDC}")
                            print(f"{Colors.RED}    ââ Unauthorized modification via {method}{Colors.ENDC}")
                            
                            vuln = IDORVulnerability(
                                endpoint=endpoint,
                                method=method,
                                resource_id=resource_id,
                                owner_account=owner.name,
                                attacker_account=attacker.name,
                                vulnerability_type='write',
                                response_code=attacker_response.status_code,
                                leaked_data=str(data),
                                severity='High',
                                timestamp=datetime.now().isoformat()
                            )
                            
                            self.vulnerabilities.append(vuln)
                            return vuln
                    
                    except json.JSONDecodeError:
                        pass
        
        print(f"{Colors.GREEN}[+] Write access properly denied{Colors.ENDC}")
        return None
    
    def test_idor_delete(self, endpoint_pattern: str, resource_id: str,
                         owner: AccountCredentials, attacker: AccountCredentials) -> Optional[IDORVulnerability]:
        """Test for delete IDOR vulnerability"""
        endpoint = endpoint_pattern.format(id=resource_id)
        url = urljoin(self.base_url, endpoint)
        
        print(f"\n{Colors.CYAN}[*] Testing DELETE access: {endpoint}{Colors.ENDC}")
        
        # Try to delete with attacker account
        attacker_response = self.make_request('DELETE', url, attacker)
        
        if attacker_response and attacker_response.status_code in [200, 204]:
            # Verify deletion by trying to read with owner
            owner_response = self.make_request('GET', url, owner)
            
            if owner_response and owner_response.status_code == 404:
                # Confirmed delete IDOR!
                print(f"{Colors.RED}[!] DELETE IDOR VULNERABILITY FOUND!{Colors.ENDC}")
                print(f"{Colors.RED}    ââ Unauthorized deletion of {owner.name}'s resource{Colors.ENDC}")
                
                vuln = IDORVulnerability(
                    endpoint=endpoint,
                    method='DELETE',
                    resource_id=resource_id,
                    owner_account=owner.name,
                    attacker_account=attacker.name,
                    vulnerability_type='delete',
                    response_code=attacker_response.status_code,
                    leaked_data='Resource successfully deleted',
                    severity='Critical',
                    timestamp=datetime.now().isoformat()
                )
                
                self.vulnerabilities.append(vuln)
                return vuln
        
        print(f"{Colors.GREEN}[+] Delete access properly denied{Colors.ENDC}")
        return None
    
    def _calculate_severity(self, data: str) -> str:
        """Calculate vulnerability severity based on leaked data"""
        data_lower = data.lower()
        
        # Check for highly sensitive data
        critical_count = sum(1 for keyword in self.sensitive_keywords[:6] 
                           if keyword in data_lower)
        
        if critical_count >= 2:
            return 'Critical'
        elif critical_count == 1:
            return 'High'
        elif any(keyword in data_lower for keyword in self.sensitive_keywords):
            return 'Medium'
        else:
            return 'Low'
    
    def run_comprehensive_test(self, custom_ids: List[str] = None):
        """Run comprehensive two-account IDOR testing"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}[*] Starting Comprehensive IDOR Testing...{Colors.ENDC}")
        
        # Step 1: Discover user IDs
        if not self.account_a.user_id:
            self.account_a.user_id = self.discover_user_id(self.account_a)
        
        if not self.account_b.user_id:
            self.account_b.user_id = self.discover_user_id(self.account_b)
        
        # Step 2: Test with known IDs
        test_ids = []
        if self.account_a.user_id:
            test_ids.append(self.account_a.user_id)
        if custom_ids:
            test_ids.extend(custom_ids)
        
        if not test_ids:
            print(f"{Colors.YELLOW}[!] No IDs to test. Please provide custom IDs or ensure auto-discovery works{Colors.ENDC}")
            return
        
        # Step 3: Test all patterns with Account A's IDs using Account B
        for resource_id in test_ids:
            print(f"\n{Colors.BOLD}{'='*70}{Colors.ENDC}")
            print(f"{Colors.BOLD}{Colors.YELLOW}[*] Testing Resource ID: {resource_id}{Colors.ENDC}")
            print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}")
            
            for pattern in self.test_patterns:
                # Test Read IDOR
                self.test_idor_read(pattern, resource_id, self.account_a, self.account_b)
                
                # Test Write IDOR (careful!)
                # self.test_idor_write(pattern, resource_id, self.account_a, self.account_b)
        
        # Step 4: If possible, create test resources and test access
        print(f"\n{Colors.BOLD}{Colors.CYAN}[*] Testing with dynamically created resources...{Colors.ENDC}")
        resource_id = self.create_test_resource(self.account_a, '/api/documents')
        
        if resource_id:
            for pattern in self.test_patterns:
                self.test_idor_read(pattern, resource_id, self.account_a, self.account_b)
    
    def generate_report(self, output_file: str = None):
        """Generate comprehensive vulnerability report"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.CYAN}                    VULNERABILITY REPORT{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.ENDC}\n")
        
        if not self.vulnerabilities:
            print(f"{Colors.GREEN}[+] No IDOR vulnerabilities found!{Colors.ENDC}")
            print(f"{Colors.GREEN}[+] All tested endpoints properly enforce access control.{Colors.ENDC}")
            return
        
        print(f"{Colors.RED}[!] Found {len(self.vulnerabilities)} IDOR Vulnerabilities!{Colors.ENDC}\n")
        
        # Group by severity
        critical = [v for v in self.vulnerabilities if v.severity == 'Critical']
        high = [v for v in self.vulnerabilities if v.severity == 'High']
        medium = [v for v in self.vulnerabilities if v.severity == 'Medium']
        low = [v for v in self.vulnerabilities if v.severity == 'Low']
        
        print(f"{Colors.RED}Critical: {len(critical)}{Colors.ENDC}")
        print(f"{Colors.YELLOW}High: {len(high)}{Colors.ENDC}")
        print(f"{Colors.CYAN}Medium: {len(medium)}{Colors.ENDC}")
        print(f"{Colors.GREEN}Low: {len(low)}{Colors.ENDC}\n")
        
        # Detailed findings
        for i, vuln in enumerate(self.vulnerabilities, 1):
            print(f"\n{Colors.BOLD}[{i}] {vuln.vulnerability_type.upper()} IDOR - {vuln.severity} Severity{Colors.ENDC}")
            print(f"    Endpoint: {vuln.endpoint}")
            print(f"    Method: {vuln.method}")
            print(f"    Resource Owner: {vuln.owner_account}")
            print(f"    Attacker Account: {vuln.attacker_account}")
            print(f"    Resource ID: {vuln.resource_id}")
            print(f"    Response Code: {vuln.response_code}")
            print(f"    Timestamp: {vuln.timestamp}")
            if vuln.leaked_data:
                print(f"    Leaked Data Preview: {vuln.leaked_data[:150]}...")
        
        # Generate JSON report if requested
        if output_file:
            report_data = {
                'scan_info': {
                    'target': self.base_url,
                    'timestamp': datetime.now().isoformat(),
                    'total_requests': self.request_count,
                    'account_a': self.account_a.name,
                    'account_b': self.account_b.name,
                },
                'summary': {
                    'total_vulnerabilities': len(self.vulnerabilities),
                    'critical': len(critical),
                    'high': len(high),
                    'medium': len(medium),
                    'low': len(low),
                },
                'vulnerabilities': [
                    {
                        'endpoint': v.endpoint,
                        'method': v.method,
                        'type': v.vulnerability_type,
                        'severity': v.severity,
                        'resource_id': v.resource_id,
                        'owner': v.owner_account,
                        'attacker': v.attacker_account,
                        'response_code': v.response_code,
                        'leaked_data': v.leaked_data,
                        'timestamp': v.timestamp,
                    }
                    for v in self.vulnerabilities
                ]
            }
            
            with open(output_file, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            print(f"\n{Colors.GREEN}[+] Report saved to: {output_file}{Colors.ENDC}")
        
        print(f"\n{Colors.YELLOW}[*] Total Requests Made: {self.request_count}{Colors.ENDC}")
        print(f"{Colors.CYAN}[*] Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}\n")

def main():
    parser = argparse.ArgumentParser(
        description='REVUEX IDOR Hunter - Two-Account Access Control Testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic two-account testing
  python idor_hunter.py -u https://api.example.com \\
    --account-a "Bearer token_a" "cookie_a=value" \\
    --account-b "Bearer token_b" "cookie_b=value"
  
  # With custom resource IDs
  python idor_hunter.py -u https://api.example.com \\
    --account-a "Bearer token_a" "session_a=xyz" \\
    --account-b "Bearer token_b" "session_b=abc" \\
    --ids 123 456 789
  
  # With JSON output
  python idor_hunter.py -u https://api.example.com \\
    --account-a "Bearer token_a" "" \\
    --account-b "Bearer token_b" "" \\
    -o report.json

Author: G33L0 (@x0x0h33l0)
Part of REVUEX Framework
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target base URL')
    parser.add_argument('--account-a', nargs=2, required=True, 
                       metavar=('AUTH_HEADER', 'COOKIES'),
                       help='Account A credentials: "Authorization: Bearer token" "cookie=value"')
    parser.add_argument('--account-b', nargs=2, required=True,
                       metavar=('AUTH_HEADER', 'COOKIES'),
                       help='Account B credentials: "Authorization: Bearer token" "cookie=value"')
    parser.add_argument('--ids', nargs='+', help='Custom resource IDs to test')
    parser.add_argument('--delay', type=float, default=1.0,
                       help='Delay between requests in seconds (default: 1.0)')
    parser.add_argument('-o', '--output', help='Output JSON report file')
    
    args = parser.parse_args()
    
    # Parse account credentials
    def parse_auth(auth_str: str) -> Dict[str, str]:
        if not auth_str:
            return {}
        if ':' in auth_str:
            key, value = auth_str.split(':', 1)
            return {key.strip(): value.strip()}
        return {'Authorization': auth_str}
    
    def parse_cookies(cookie_str: str) -> Dict[str, str]:
        if not cookie_str:
            return {}
        cookies = {}
        for item in cookie_str.split(';'):
            if '=' in item:
                key, value = item.split('=', 1)
                cookies[key.strip()] = value.strip()
        return cookies
    
    account_a = AccountCredentials(
        name='Account A',
        auth_header=parse_auth(args.account_a[0]),
        cookies=parse_cookies(args.account_a[1])
    )
    
    account_b = AccountCredentials(
        name='Account B',
        auth_header=parse_auth(args.account_b[0]),
        cookies=parse_cookies(args.account_b[1])
    )
    
    # Initialize hunter
    hunter = IDORHunter(args.url, account_a, account_b, delay=args.delay)
    hunter.print_banner()
    
    try:
        # Run comprehensive testing
        hunter.run_comprehensive_test(custom_ids=args.ids)
        
        # Generate report
        hunter.generate_report(output_file=args.output)
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.ENDC}")
        hunter.generate_report(output_file=args.output)
        sys.exit(0)
    
    except Exception as e:
        print(f"\n{Colors.RED}[!] Error: {e}{Colors.ENDC}")
        sys.exit(1)

if __name__ == '__main__':
    main()
