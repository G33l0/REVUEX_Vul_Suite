#!/usr/bin/env python3
"""
REVUEX - SubdomainHunter Pro
Advanced Subdomain Discovery & Enumeration

Author: G33L0
Telegram: @x0x0h33l0
"""

import requests
import time
import json
import urllib3
import re
from pathlib import Path
from urllib.parse import urlparse

# Suppress SSL warnings for validation phase
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SubdomainHunter:
    """Advanced subdomain discovery tool"""
    
    def __init__(self, target, workspace, delay=2):
        self.target = target
        self.workspace = Path(workspace)
        self.delay = delay
        self.subdomains = set()
        self.headers = {
            'User-Agent': 'REVUEX-SubdomainHunter/1.0 (Security Research; +https://github.com/G33L0)'
        }
    
    def discover(self):
        """Discover subdomains using multiple techniques"""
        print(f"\n{'='*60}")
        print(f"📡 REVUEX SubdomainHunter: {self.target}")
        print(f"{'='*60}")
        
        # Ensure workspace exists before starting
        self.workspace.mkdir(parents=True, exist_ok=True)
        
        # Technique 1: Certificate Transparency Logs
        self._crt_sh_search()
        time.sleep(self.delay)
        
        # Technique 2: DNS Enumeration
        self._dns_enumeration()
        time.sleep(self.delay)
        
        # Technique 3: Web Archives
        self._web_archive_search()
        time.sleep(self.delay)
        
        # Technique 4: Search Engine Dorking
        self._search_engine_dork()
        
        # Validate discovered subdomains
        valid_subdomains = self._validate_subdomains()
        
        # Save results
        self._save_results(valid_subdomains)
        
        return list(valid_subdomains)
    
    def _crt_sh_search(self):
        """Search Certificate Transparency logs via crt.sh"""
        try:
            print("    → Searching Certificate Transparency logs...")
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip().replace('*.', '')
                        if subdomain.endswith(self.target):
                            self.subdomains.add(subdomain.lower())
                print(f"    ✓ Found {len(self.subdomains)} unique names from CT logs")
        except Exception as e:
            print(f"    ! CT logs search error: {str(e)}")

    def _dns_enumeration(self):
        """DNS enumeration using common subdomain wordlist"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'ns1', 'cpanel', 
            'whm', 'dev', 'admin', 'vpn', 'mysql', 'staging', 'api', 'cdn', 'test',
            'support', 'portal', 'remote', 'db', 'app', 'owa', 'api-gateway'
        ]
        print(f"    → DNS enumeration with {len(common_subdomains)} common names...")
        found = 0
        for sub in common_subdomains:
            subdomain = f"{sub}.{self.target}".lower()
            try:
                # Use HEAD request for speed
                requests.head(f"http://{subdomain}", timeout=2, allow_redirects=True)
                self.subdomains.add(subdomain)
                found += 1
            except: continue
        print(f"    ✓ Added {found} subdomains via DNS check")

    def _web_archive_search(self):
        """Search web archives for historical subdomains"""
        try:
            print("    → Searching web archives (Wayback Machine)...")
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.target}/*&output=json&collapse=urlkey"
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                initial_count = len(self.subdomains)
                for entry in data[1:]:  # Skip header
                    if len(entry) > 2:
                        # Extract hostname from the URL field
                        archived_url = entry[2]
                        hostname = urlparse(archived_url if "://" in archived_url else f"http://{archived_url}").netloc
                        hostname = hostname.split(':')[0] # Remove port if present
                        if hostname.endswith(self.target):
                            self.subdomains.add(hostname.lower())
                
                print(f"    ✓ Found {len(self.subdomains) - initial_count} new subdomains from archives")
        except Exception as e:
            print(f"    ! Web archive search error: {str(e)}")

    def _search_engine_dork(self):
        """Passive search engine enumeration (Logic preserved)"""
        print("    → Search engine dorking (passive variations)...")
        variations = ['www', 'api', 'dev', 'staging', 'prod']
        for var in variations:
            self.subdomains.add(f"{var}.{self.target}".lower())

    def _validate_subdomains(self):
        """Validate discovered subdomains are responsive"""
        print(f"    → Validating {len(self.subdomains)} total discovered entries...")
        valid = set()
        for subdomain in self.subdomains:
            if not subdomain: continue
            try:
                # Use a single check with verify=False to handle all cert states
                url = f"http://{subdomain}"
                response = requests.get(url, timeout=4, verify=False, allow_redirects=True)
                if response.status_code < 500:
                    valid.add(subdomain)
            except: continue
        print(f"    ✓ Validated {len(valid)} active subdomains")
        return valid

    def _save_results(self, subdomains):
        """Save subdomain results"""
        txt_file = self.workspace / "subdomains.txt"
        with open(txt_file, 'w') as f:
            for sub in sorted(subdomains):
                f.write(f"{sub}\n")
        
        json_file = self.workspace / "subdomains.json"
        with open(json_file, 'w') as f:
            json.dump({
                'target': self.target,
                'total_found': len(subdomains),
                'subdomains': sorted(list(subdomains))
            }, f, indent=2)
        print(f"\n💾 Results saved to: {self.workspace}/")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python subdomain_hunter.py <domain>")
        sys.exit(1)
    
    hunter = SubdomainHunter(sys.argv[1], Path("revuex_workspace"))
    hunter.discover()
