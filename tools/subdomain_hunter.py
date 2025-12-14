#!/usr/bin/env python3
"""
REVUEX - SubdomainHunter Pro
Advanced Subdomain Discovery & Enumeration

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
"""

import requests
import subprocess
import time
import json
from pathlib import Path
from urllib.parse import urlparse

class SubdomainHunter:
    """Advanced subdomain discovery tool"""
    
    def __init__(self, target, workspace, delay=2):
        """
        Initialize SubdomainHunter
        
        Args:
            target: Target domain
            workspace: Workspace directory
            delay: Delay between requests
        """
        self.target = target
        self.workspace = Path(workspace)
        self.delay = delay
        self.subdomains = set()
        
        # User agent
        self.headers = {
            'User-Agent': 'REVUEX-SubdomainHunter/1.0 (Security Research; +https://github.com/G33L0)'
        }
    
    def discover(self):
        """Discover subdomains using multiple techniques"""
        print(f"    [*] Starting subdomain discovery for {self.target}")
        
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
            print("        → Searching Certificate Transparency logs...")
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    # Handle wildcard and multiple names
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip().replace('*.', '')
                        if subdomain.endswith(self.target):
                            self.subdomains.add(subdomain)
                
                print(f"        ✓ Found {len(self.subdomains)} subdomains from CT logs")
        except Exception as e:
            print(f"        ! CT logs search error: {str(e)}")
    
    def _dns_enumeration(self):
        """DNS enumeration using common subdomain wordlist"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
            'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx',
            'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar',
            'wiki', 'web', 'media', 'email', 'images', 'img', 'www1', 'intranet',
            'portal', 'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4',
            'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my',
            'svn', 'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup',
            'mx2', 'lyncdiscover', 'info', 'apps', 'download', 'remote', 'db', 'forums',
            'store', 'relay', 'files', 'newsletter', 'app', 'live', 'owa', 'en', 'start',
            'sms', 'office', 'exchange', 'ipv4', 'help', 'home', 'payment', 'api-gateway'
        ]
        
        print(f"        → DNS enumeration with {len(common_subdomains)} common names...")
        found = 0
        
        for sub in common_subdomains:
            subdomain = f"{sub}.{self.target}"
            try:
                # Simple DNS check using requests
                test_url = f"http://{subdomain}"
                requests.head(test_url, timeout=3, allow_redirects=True)
                self.subdomains.add(subdomain)
                found += 1
            except:
                pass
        
        print(f"        ✓ Found {found} subdomains via DNS enumeration")
    
    def _web_archive_search(self):
        """Search web archives for historical subdomains"""
        try:
            print("        → Searching web archives...")
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.target}/*&output=json&collapse=urlkey"
            
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                initial_count = len(self.subdomains)
                
                for entry in data[1:]:  # Skip header
                    if len(entry) > 2:
                        archived_url = entry[2]
                        try:
                            parsed = urlparse(archived_url)
                            hostname = parsed.netloc
                            if hostname.endswith(self.target):
                                self.subdomains.add(hostname)
                        except:
                            pass
                
                new_found = len(self.subdomains) - initial_count
                print(f"        ✓ Found {new_found} subdomains from web archives")
        except Exception as e:
            print(f"        ! Web archive search error: {str(e)}")
    
    def _search_engine_dork(self):
        """Passive search engine enumeration"""
        # Simulate search engine results (in real implementation, use APIs)
        print("        → Search engine dorking (passive)...")
        
        # Add main domain variations
        variations = [
            f"www.{self.target}",
            f"api.{self.target}",
            f"dev.{self.target}",
            f"staging.{self.target}",
            f"prod.{self.target}"
        ]
        
        for var in variations:
            self.subdomains.add(var)
    
    def _validate_subdomains(self):
        """Validate discovered subdomains are responsive"""
        print(f"        → Validating {len(self.subdomains)} discovered subdomains...")
        
        valid = set()
        
        for subdomain in self.subdomains:
            try:
                # Try both HTTP and HTTPS
                for scheme in ['https', 'http']:
                    url = f"{scheme}://{subdomain}"
                    try:
                        response = requests.head(url, timeout=5, allow_redirects=True, verify=False)
                        if response.status_code < 500:  # Accept any non-server-error response
                            valid.add(subdomain)
                            break
                    except:
                        continue
            except:
                pass
        
        print(f"        ✓ Validated {len(valid)} active subdomains")
        return valid
    
    def _save_results(self, subdomains):
        """Save subdomain results"""
        output_file = self.workspace / "subdomains.txt"
        with open(output_file, 'w') as f:
            for subdomain in sorted(subdomains):
                f.write(f"{subdomain}\n")
        
        # Also save as JSON
        json_file = self.workspace / "subdomains.json"
        with open(json_file, 'w') as f:
            json.dump({
                'target': self.target,
                'total_found': len(subdomains),
                'subdomains': sorted(list(subdomains))
            }, f, indent=2)
