#!/usr/bin/env python3
"""
REVUEX - JavaScript Secrets Miner
Extract API Endpoints, Keys, Tokens & Secrets from JavaScript

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
"""

import requests
import re
import json
from pathlib import Path
from urllib.parse import urljoin, urlparse
import base64

class JSSecretsMiner:
    """Mine secrets and endpoints from JavaScript files"""
    
    def __init__(self, target, workspace, delay=2):
        """
        Initialize JavaScript Secrets Miner
        
        Args:
            target: Target URL/domain
            workspace: Workspace directory
            delay: Delay between requests
        """
        self.target = target if target.startswith('http') else f"https://{target}"
        self.workspace = Path(workspace)
        self.delay = delay
        
        self.headers = {
            'User-Agent': 'REVUEX-JSSecretsMiner/1.0 (Security Research; +https://github.com/G33L0)'
        }
        
        # Regex patterns for secret detection
        self.patterns = {
            'api_keys': [
                r'api[_-]?key["\s:=]+(["\']?)([a-zA-Z0-9_\-]{20,})\1',
                r'apikey["\s:=]+(["\']?)([a-zA-Z0-9_\-]{20,})\1',
                r'api[_-]?secret["\s:=]+(["\']?)([a-zA-Z0-9_\-]{20,})\1',
            ],
            'aws_keys': [
                r'AKIA[0-9A-Z]{16}',  # AWS Access Key
                r'aws[_-]?access[_-]?key[_-]?id["\s:=]+(["\']?)([A-Z0-9]{20})\1',
                r'aws[_-]?secret[_-]?access[_-]?key["\s:=]+(["\']?)([A-Za-z0-9/+=]{40})\1',
            ],
            'tokens': [
                r'token["\s:=]+(["\']?)([a-zA-Z0-9_\-\.]{20,})\1',
                r'access[_-]?token["\s:=]+(["\']?)([a-zA-Z0-9_\-\.]{20,})\1',
                r'auth[_-]?token["\s:=]+(["\']?)([a-zA-Z0-9_\-\.]{20,})\1',
                r'bearer["\s:=]+(["\']?)([a-zA-Z0-9_\-\.]{20,})\1',
            ],
            'jwt_tokens': [
                r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',  # JWT pattern
            ],
            'google_api': [
                r'AIza[0-9A-Za-z\-_]{35}',  # Google API Key
            ],
            'github_tokens': [
                r'ghp_[0-9a-zA-Z]{36}',  # GitHub Personal Access Token
                r'gho_[0-9a-zA-Z]{36}',  # GitHub OAuth Token
            ],
            'slack_tokens': [
                r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}',
            ],
            'stripe_keys': [
                r'sk_live_[0-9a-zA-Z]{24,}',
                r'pk_live_[0-9a-zA-Z]{24,}',
            ],
            'passwords': [
                r'password["\s:=]+(["\']?)([^\s"\']{6,})\1',
                r'passwd["\s:=]+(["\']?)([^\s"\']{6,})\1',
                r'pwd["\s:=]+(["\']?)([^\s"\']{6,})\1',
            ],
            'private_keys': [
                r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            ],
            'database_urls': [
                r'mongodb(\+srv)?://[^\s"\']+',
                r'mysql://[^\s"\']+',
                r'postgres(?:ql)?://[^\s"\']+',
                r'redis://[^\s"\']+',
            ],
            'endpoints': [
                r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s"\'<>]*)?',
                r'/api/v?\d+/[a-zA-Z0-9\-_/]+',
                r'/v\d+/[a-zA-Z0-9\-_/]+',
                r'graphql',
                r'/rest/[a-zA-Z0-9\-_/]+',
            ],
            'ip_addresses': [
                r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            ],
            'email_addresses': [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            ],
            's3_buckets': [
                r's3://[a-zA-Z0-9\-\.]+',
                r'[a-zA-Z0-9\-\.]+\.s3\.amazonaws\.com',
                r's3\.amazonaws\.com/[a-zA-Z0-9\-\.]+',
            ],
            'cloudfront': [
                r'[a-zA-Z0-9]+\.cloudfront\.net',
            ],
        }
    
    def mine(self):
        """Mine JavaScript files for secrets and endpoints"""
        findings = {
            'target': self.target,
            'js_files': [],
            'endpoints': [],
            'secrets': {
                'api_keys': [],
                'aws_keys': [],
                'tokens': [],
                'jwt_tokens': [],
                'google_api': [],
                'github_tokens': [],
                'slack_tokens': [],
                'stripe_keys': [],
                'passwords': [],
                'private_keys': [],
                'database_urls': [],
                's3_buckets': [],
                'cloudfront': [],
            },
            'emails': [],
            'ip_addresses': [],
            'internal_paths': [],
        }
        
        try:
            # Get main page
            response = requests.get(
                self.target,
                headers=self.headers,
                timeout=10,
                verify=False
            )
            
            html = response.text
            
            # Find all JavaScript files
            js_files = self._find_js_files(html)
            findings['js_files'] = js_files
            
            # Download and analyze each JS file
            for js_url in js_files[:20]:  # Limit to first 20 files
                try:
                    js_content = self._download_js(js_url)
                    if js_content:
                        self._analyze_js(js_content, findings)
                except Exception as e:
                    continue
            
            # Analyze main HTML too
            self._analyze_js(html, findings)
            
            # Remove duplicates
            findings = self._deduplicate_findings(findings)
            
        except Exception as e:
            findings['error'] = str(e)
        
        # Save results
        self._save_results(findings)
        
        return findings
    
    def _find_js_files(self, html):
        """Find all JavaScript file URLs in HTML"""
        js_files = set()
        
        # Find <script src="...">
        script_pattern = r'<script[^>]+src=["\'](.*?)["\']'
        matches = re.findall(script_pattern, html, re.IGNORECASE)
        
        for match in matches:
            if match.endswith('.js') or 'javascript' in match:
                full_url = urljoin(self.target, match)
                js_files.add(full_url)
        
        # Find inline references to .js files
        js_pattern = r'["\']((?:/|https?://)[^"\']*\.js)["\']'
        matches = re.findall(js_pattern, html)
        
        for match in matches:
            full_url = urljoin(self.target, match)
            js_files.add(full_url)
        
        return list(js_files)
    
    def _download_js(self, url):
        """Download JavaScript file"""
        try:
            response = requests.get(
                url,
                headers=self.headers,
                timeout=10,
                verify=False
            )
            
            if response.status_code == 200:
                return response.text
        except:
            pass
        
        return None
    
    def _analyze_js(self, content, findings):
        """Analyze JavaScript content for secrets"""
        
        # Extract API keys
        for pattern in self.patterns['api_keys']:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                key = match[1] if isinstance(match, tuple) else match
                if key and len(key) > 15:
                    findings['secrets']['api_keys'].append(key)
        
        # Extract AWS keys
        for pattern in self.patterns['aws_keys']:
            matches = re.findall(pattern, content)
            for match in matches:
                key = match[1] if isinstance(match, tuple) and len(match) > 1 else match
                if key:
                    findings['secrets']['aws_keys'].append(key)
        
        # Extract tokens
        for pattern in self.patterns['tokens']:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                token = match[1] if isinstance(match, tuple) else match
                if token and len(token) > 15:
                    findings['secrets']['tokens'].append(token)
        
        # Extract JWT tokens
        for pattern in self.patterns['jwt_tokens']:
            matches = re.findall(pattern, content)
            for match in matches:
                findings['secrets']['jwt_tokens'].append(match)
        
        # Extract Google API keys
        for pattern in self.patterns['google_api']:
            matches = re.findall(pattern, content)
            findings['secrets']['google_api'].extend(matches)
        
        # Extract GitHub tokens
        for pattern in self.patterns['github_tokens']:
            matches = re.findall(pattern, content)
            findings['secrets']['github_tokens'].extend(matches)
        
        # Extract Slack tokens
        for pattern in self.patterns['slack_tokens']:
            matches = re.findall(pattern, content)
            findings['secrets']['slack_tokens'].extend(matches)
        
        # Extract Stripe keys
        for pattern in self.patterns['stripe_keys']:
            matches = re.findall(pattern, content)
            findings['secrets']['stripe_keys'].extend(matches)
        
        # Extract passwords (carefully - high false positive rate)
        for pattern in self.patterns['passwords']:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                pwd = match[1] if isinstance(match, tuple) else match
                # Filter out common false positives
                if pwd and len(pwd) > 5 and pwd not in ['password', 'Password', '******']:
                    findings['secrets']['passwords'].append(pwd)
        
        # Extract private keys
        for pattern in self.patterns['private_keys']:
            if re.search(pattern, content):
                findings['secrets']['private_keys'].append('PRIVATE KEY FOUND')
        
        # Extract database URLs
        for pattern in self.patterns['database_urls']:
            matches = re.findall(pattern, content)
            findings['secrets']['database_urls'].extend(matches)
        
        # Extract S3 buckets
        for pattern in self.patterns['s3_buckets']:
            matches = re.findall(pattern, content)
            findings['secrets']['s3_buckets'].extend(matches)
        
        # Extract CloudFront distributions
        for pattern in self.patterns['cloudfront']:
            matches = re.findall(pattern, content)
            findings['secrets']['cloudfront'].extend(matches)
        
        # Extract endpoints
        for pattern in self.patterns['endpoints']:
            matches = re.findall(pattern, content)
            for match in matches:
                # Clean and validate endpoint
                endpoint = match.strip()
                if endpoint and len(endpoint) > 5:
                    findings['endpoints'].append(endpoint)
        
        # Extract email addresses
        for pattern in self.patterns['email_addresses']:
            matches = re.findall(pattern, content)
            findings['emails'].extend(matches)
        
        # Extract IP addresses
        for pattern in self.patterns['ip_addresses']:
            matches = re.findall(pattern, content)
            findings['ip_addresses'].extend(matches)
    
    def _deduplicate_findings(self, findings):
        """Remove duplicate findings"""
        
        # Deduplicate lists
        findings['js_files'] = list(set(findings['js_files']))
        findings['endpoints'] = list(set(findings['endpoints']))
        findings['emails'] = list(set(findings['emails']))
        findings['ip_addresses'] = list(set(findings['ip_addresses']))
        
        # Deduplicate secrets
        for key in findings['secrets']:
            findings['secrets'][key] = list(set(findings['secrets'][key]))
        
        return findings
    
    def _save_results(self, findings):
        """Save mining results"""
        # Create secrets directory
        secrets_dir = self.workspace / "js_secrets"
        secrets_dir.mkdir(exist_ok=True)
        
        # Safe filename from URL
        safe_name = re.sub(r'[^\w\-]', '_', urlparse(self.target).netloc)
        output_file = secrets_dir / f"{safe_name}_secrets.json"
        
        with open(output_file, 'w') as f:
            json.dump(findings, f, indent=2)
        
        # Also create a summary file with high-value findings
        summary = {
            'target': self.target,
            'critical_findings': [],
        }
        
        # Flag critical findings
        if findings['secrets']['aws_keys']:
            summary['critical_findings'].append({
                'type': 'AWS Keys',
                'severity': 'CRITICAL',
                'count': len(findings['secrets']['aws_keys'])
            })
        
        if findings['secrets']['private_keys']:
            summary['critical_findings'].append({
                'type': 'Private Keys',
                'severity': 'CRITICAL',
                'count': len(findings['secrets']['private_keys'])
            })
        
        if findings['secrets']['database_urls']:
            summary['critical_findings'].append({
                'type': 'Database URLs',
                'severity': 'HIGH',
                'count': len(findings['secrets']['database_urls'])
            })
        
        if findings['secrets']['api_keys']:
            summary['critical_findings'].append({
                'type': 'API Keys',
                'severity': 'HIGH',
                'count': len(findings['secrets']['api_keys'])
            })
        
        summary_file = secrets_dir / f"{safe_name}_summary.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
