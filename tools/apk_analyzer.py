#!/usr/bin/env python3
"""
REVUEX - Android APK Analyzer
Mobile Application Security Analysis

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
"""

import requests
import json
import re
import zipfile
import tempfile
import shutil
from pathlib import Path
import os

class APKAnalyzer:
    """Android APK security analysis"""

    def __init__(self, target, apk_urls, workspace, delay=2):
        """
        Initialize APK Analyzer
        
        Args:
            target: Target URL/domain
            apk_urls: List of APK URLs or paths
            workspace: Workspace directory
            delay: Delay between requests
        """
        self.target = target if target.startswith('http') else f"https://{target}"
        self.apk_urls = apk_urls if isinstance(apk_urls, list) else [apk_urls]
        self.workspace = Path(workspace)
        self.delay = delay
        
        self.headers = {
            'User-Agent': 'REVUEX-APKAnalyzer/1.0 (Security Research; +https://github.com/G33L0)'
        }
        
        # Patterns for secret detection
        self.secret_patterns = {
            'api_keys': [
                r'api[_-]?key["\s:=]+(["\']?)([a-zA-Z0-9_\-]{20,})\1',
                r'apikey["\s:=]+(["\']?)([a-zA-Z0-9_\-]{20,})\1',
            ],
            'aws_keys': [
                r'AKIA[0-9A-Z]{16}',
                r'aws[_-]?access[_-]?key',
                r'aws[_-]?secret[_-]?key',
            ],
            'tokens': [
                r'token["\s:=]+(["\']?)([a-zA-Z0-9_\-\.]{20,})\1',
                r'auth[_-]?token["\s:=]+(["\']?)([a-zA-Z0-9_\-\.]{20,})\1',
            ],
            'database_urls': [
                r'mongodb(\+srv)?://[^\s"\']+',
                r'mysql://[^\s"\']+',
                r'postgres(?:ql)?://[^\s"\']+',
            ],
            'firebase': [
                r'firebaseio\.com',
                r'firebase[_-]?url',
                r'firebase[_-]?api[_-]?key',
            ],
            'endpoints': [
                r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s"\'<>]*)?',
                r'/api/v?\d+/[a-zA-Z0-9\-_/]+',
            ],
            'keys': [
                r'private[_-]?key',
                r'secret[_-]?key',
                r'encryption[_-]?key',
            ],
            'passwords': [
                r'password["\s:=]+(["\']?)([^\s"\']{6,})\1',
            ],
        }

    def scan(self):
        """Scan APK for security issues"""
        vulnerabilities = []
        
        if not self.apk_urls:
            print("! No APK URLs provided")
            return vulnerabilities
        
        for apk_url in self.apk_urls[:3]:  # Limit to first 3 APKs
            print(f"→ Analyzing APK: {apk_url}")
            
            # Download APK
            apk_path = self._download_apk(apk_url)
            
            if not apk_path:
                print("! Failed to download APK")
                continue
            
            # Extract APK contents
            extract_dir = self._extract_apk(apk_path)
            
            if not extract_dir:
                print("! Failed to extract APK")
                continue
            
            # Analyze APK
            apk_vulns = self._analyze_apk(extract_dir, apk_url, apk_path)
            vulnerabilities.extend(apk_vulns)
            
            # Cleanup
            try:
                shutil.rmtree(extract_dir)
                os.remove(apk_path)
            except:
                pass
        
        # Save results
        self._save_results(vulnerabilities)
        return vulnerabilities

    def _download_apk(self, apk_url):
        """Download APK file"""
        try:
            if apk_url.startswith('http'):
                response = requests.get(
                    apk_url,
                    headers=self.headers,
                    timeout=30,
                    stream=True,
                    verify=False
                )
                
                if response.status_code == 200:
                    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.apk')
                    for chunk in response.iter_content(chunk_size=8192):
                        temp_file.write(chunk)
                    temp_file.close()
                    return temp_file.name
            else:
                # Local file path
                if os.path.exists(apk_url):
                    return apk_url
        except Exception as e:
            print(f"! Download error: {str(e)}")
        return None

    def _extract_apk(self, apk_path):
        """Extract APK contents"""
        try:
            extract_dir = tempfile.mkdtemp()
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            return extract_dir
        except Exception as e:
            print(f"! Extract error: {str(e)}")
            return None

    def _analyze_apk(self, extract_dir, apk_url, apk_path):
        """Analyze extracted APK contents"""
        vulnerabilities = []
        
        vulnerabilities.extend(self._analyze_manifest(extract_dir, apk_url, apk_path))
        vulnerabilities.extend(self._find_hardcoded_secrets(extract_dir, apk_url, apk_path))
        vulnerabilities.extend(self._find_api_endpoints(extract_dir, apk_url, apk_path))
        vulnerabilities.extend(self._check_debug_mode(extract_dir))
        vulnerabilities.extend(self._check_ssl_pinning(extract_dir, apk_url, apk_path))
        
        for vuln in vulnerabilities:
            vuln['apk_url'] = apk_url
            vuln['url'] = self.target
        
        return vulnerabilities

    # ------------------------------
    # Manifest & Security Checks
    # ------------------------------

    def _analyze_manifest(self, extract_dir, apk_url, apk_path):
        """Analyze AndroidManifest.xml"""
        vulnerabilities = []
        manifest_path = Path(extract_dir) / "AndroidManifest.xml"
        if not manifest_path.exists():
            return vulnerabilities
        
        try:
            with open(manifest_path, 'rb') as f:
                manifest_content = f.read()
            manifest_str = str(manifest_content)
            
            # Debuggable flag
            if 'debuggable' in manifest_str.lower():
                vulnerabilities.append({
                    'type': 'Android App Debuggable',
                    'severity': 'high',
                    'description': 'Application is marked as debuggable in AndroidManifest.xml',
                    'evidence': 'android:debuggable="true"',
                    'steps_to_reproduce': ["Download APK", "Check AndroidManifest.xml"],
                    'remediation': ['Set android:debuggable="false" in production'],
                    'tags': ['android', 'debug']
                })
            
            # Backup enabled
            if 'allowBackup' in manifest_str:
                vulnerabilities.append({
                    'type': 'Android Backup Enabled',
                    'severity': 'medium',
                    'description': 'Application allows backup of data via ADB',
                    'evidence': 'android:allowBackup="true"',
                    'steps_to_reproduce': ["Download APK", "Create backup using adb backup"],
                    'remediation': ['Set android:allowBackup="false"'],
                    'tags': ['android', 'backup']
                })
            
            # Exported components
            if 'exported="true"' in manifest_str:
                vulnerabilities.append({
                    'type': 'Exported Android Components',
                    'severity': 'medium',
                    'description': 'Application has exported components accessible without authentication',
                    'evidence': 'android:exported="true"',
                    'steps_to_reproduce': ["Decompile APK", "Check exported components"],
                    'remediation': ['Set android:exported="false" or require permissions'],
                    'tags': ['android', 'components']
                })
        
        except Exception:
            pass
        
        return vulnerabilities

    # ------------------------------
    # Secret & Endpoint Checks
    # ------------------------------

    def _find_hardcoded_secrets(self, extract_dir, apk_url, apk_path):
        vulnerabilities = []
        secrets_found = {k: [] for k in self.secret_patterns}
        
        search_paths = [
            Path(extract_dir) / "res" / "values",
            Path(extract_dir) / "assets",
            Path(extract_dir) / "resources.arsc",
        ]
        
        for search_path in search_paths:
            if not search_path.exists():
                continue
            files = [search_path] if search_path.is_file() else list(search_path.rglob('*'))
            for file_path in files:
                if not file_path.is_file():
                    continue
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                    for secret_type, patterns in self.secret_patterns.items():
                        for pattern in patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            for match in matches:
                                secret = match[1] if isinstance(match, tuple) and len(match) > 1 else match
                                if secret and len(str(secret)) > 10:
                                    secrets_found[secret_type].append({
                                        'value': str(secret)[:50],
                                        'file': str(file_path.relative_to(extract_dir))
                                    })
                except:
                    continue
        
        # Generate vulnerabilities for secrets
        for key_type in ['api_keys', 'aws_keys', 'database_urls', 'firebase']:
            if secrets_found[key_type]:
                sample = secrets_found[key_type][0]
                vulnerabilities.append({
                    'type': f'Hardcoded {key_type.replace("_", " ").title()}',
                    'severity': 'critical' if key_type in ['api_keys', 'aws_keys'] else 'high',
                    'description': f'{key_type.replace("_", " ").title()} found hardcoded in APK',
                    'evidence': f'Found {len(secrets_found[key_type])} in {sample["file"]}',
                    'steps_to_reproduce': ["Download APK", f"Inspect {sample['file']}"],
                    'remediation': ['Remove hardcoded secrets and use secure storage/backend'],
                    'tags': ['android', 'hardcoded_secrets']
                })
        
        return vulnerabilities

    def _find_api_endpoints(self, extract_dir, apk_url, apk_path):
        vulnerabilities = []
        endpoints = []
        search_paths = [Path(extract_dir) / "res", Path(extract_dir) / "assets"]
        for search_path in search_paths:
            if not search_path.exists():
                continue
            for file_path in search_path.rglob('*'):
                if not file_path.is_file():
                    continue
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                    url_pattern = r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s"\'<>]*)?'
                    matches = re.findall(url_pattern, content)
                    endpoints.extend(matches)
                except:
                    continue
        if endpoints:
            unique_endpoints = list(set(endpoints))
            vulnerabilities.append({
                'type': 'API Endpoints Discovered',
                'severity': 'info',
                'description': 'API endpoints found in APK',
                'evidence': f'{len(unique_endpoints)} endpoints found',
                'steps_to_reproduce': ["Download APK", "Decompile and search for URLs"],
                'remediation': ['Secure API endpoints with authentication/authorization'],
                'tags': ['android', 'api'],
                'endpoints': unique_endpoints[:20]
            })
        return vulnerabilities

    # ------------------------------
    # Debug & SSL Checks
    # ------------------------------

    def _check_debug_mode(self, extract_dir):
        return []  # Already handled in manifest

    def _check_ssl_pinning(self, extract_dir, apk_url, apk_path):
        vulnerabilities = []
        has_pinning = False
        for file_path in Path(extract_dir).rglob('*'):
            if not file_path.is_file():
                continue
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
                if any(p in content for p in ['CertificatePinner', 'TrustManager', 'X509TrustManager']):
                    has_pinning = True
                    break
            except:
                continue
        if not has_pinning:
            vulnerabilities.append({
                'type': 'Missing SSL Certificate Pinning',
                'severity': 'medium',
                'description': 'No SSL pinning detected in APK code',
                'steps_to_reproduce': ["Setup MITM proxy and observe HTTPS traffic"],
                'remediation': ['Implement SSL certificate pinning using Network Security Config'],
                'tags': ['android', 'ssl']
            })
        return vulnerabilities

    # ------------------------------
    # Save Results
    # ------------------------------

    def _save_results(self, vulnerabilities):
        apk_dir = self.workspace / "apk_analysis"
        apk_dir.mkdir(exist_ok=True)
        output_file = apk_dir / "apk_vulnerabilities.json"
        with open(output_file, 'w') as f:
            json.dump({
                'target': self.target,
                'apks_analyzed': len(self.apk_urls),
                'vulnerabilities': vulnerabilities
            }, f, indent=2)