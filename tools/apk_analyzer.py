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
import subprocess
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
            print("            ! No APK URLs provided")
            return vulnerabilities
        
        for apk_url in self.apk_urls[:3]:  # Limit to first 3 APKs
            print(f"            → Analyzing APK: {apk_url}")
            
            # Download APK
            apk_path = self._download_apk(apk_url)
            
            if not apk_path:
                print("            ! Failed to download APK")
                continue
            
            # Extract APK contents
            extract_dir = self._extract_apk(apk_path)
            
            if not extract_dir:
                print("            ! Failed to extract APK")
                continue
            
            # Analyze APK
            apk_vulns = self._analyze_apk(extract_dir, apk_url)
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
                    # Save to temp file
                    temp_file = tempfile.NamedTemporaryFile(
                        delete=False,
                        suffix='.apk'
                    )
                    
                    for chunk in response.iter_content(chunk_size=8192):
                        temp_file.write(chunk)
                    
                    temp_file.close()
                    return temp_file.name
            else:
                # Local file path
                if os.path.exists(apk_url):
                    return apk_url
        except Exception as e:
            print(f"            ! Download error: {str(e)}")
        
        return None
    
    def _extract_apk(self, apk_path):
        """Extract APK contents"""
        try:
            # Create temp directory
            extract_dir = tempfile.mkdtemp()
            
            # Extract APK (it's a ZIP file)
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            return extract_dir
        except Exception as e:
            print(f"            ! Extract error: {str(e)}")
            return None
    
    def _analyze_apk(self, extract_dir, apk_url):
        """Analyze extracted APK contents"""
        vulnerabilities = []
        
        # 1. Analyze AndroidManifest.xml
        manifest_vulns = self._analyze_manifest(extract_dir)
        vulnerabilities.extend(manifest_vulns)
        
        # 2. Search for hardcoded secrets
        secret_vulns = self._find_hardcoded_secrets(extract_dir)
        vulnerabilities.extend(secret_vulns)
        
        # 3. Find API endpoints
        endpoint_vulns = self._find_api_endpoints(extract_dir)
        vulnerabilities.extend(endpoint_vulns)
        
        # 4. Check for debugging enabled
        debug_vulns = self._check_debug_mode(extract_dir)
        vulnerabilities.extend(debug_vulns)
        
        # 5. Check for SSL pinning
        ssl_vulns = self._check_ssl_pinning(extract_dir)
        vulnerabilities.extend(ssl_vulns)
        
        # Add source info to all vulnerabilities
        for vuln in vulnerabilities:
            vuln['apk_url'] = apk_url
            vuln['url'] = self.target
        
        return vulnerabilities
    
    def _analyze_manifest(self, extract_dir):
        """Analyze AndroidManifest.xml"""
        vulnerabilities = []
        
        manifest_path = Path(extract_dir) / "AndroidManifest.xml"
        
        if not manifest_path.exists():
            return vulnerabilities
        
        try:
            # Read manifest (note: it's binary XML, but we can still search)
            with open(manifest_path, 'rb') as f:
                manifest_content = f.read()
            
            # Convert to string for pattern matching
            manifest_str = str(manifest_content)
            
            # Check for debuggable flag
            if 'debuggable' in manifest_str.lower():
                vulnerabilities.append({
                    'type': 'Android App Debuggable',
                    'severity': 'High',
                    'description': 'Application is marked as debuggable in AndroidManifest.xml',
                    'evidence': 'android:debuggable="true" found in manifest',
                    'attack_path': [
                        'App is debuggable in production',
                        'Attacker can attach debugger to running app',
                        'Read/modify memory and variables',
                        'Bypass security controls',
                        'Extract sensitive data'
                    ],
                    'remediation': [
                        'Set android:debuggable="false" for production builds',
                        'Use build variants (debug vs release)',
                        'Implement runtime debugger detection',
                        'Obfuscate code with ProGuard/R8'
                    ],
                    'tags': ['android', 'debug', 'configuration']
                })
            
            # Check for backup enabled
            if 'allowBackup' in manifest_str:
                vulnerabilities.append({
                    'type': 'Android Backup Enabled',
                    'severity': 'Medium',
                    'description': 'Application allows backup of data via ADB',
                    'evidence': 'android:allowBackup="true" found in manifest',
                    'attack_path': [
                        'App data can be backed up via ADB',
                        'Attacker with physical access can extract data',
                        'Sensitive data may be exposed in backup files'
                    ],
                    'remediation': [
                        'Set android:allowBackup="false" for sensitive apps',
                        'Use android:fullBackupContent to exclude sensitive files',
                        'Encrypt sensitive data before storage',
                        'Implement backup encryption'
                    ],
                    'tags': ['android', 'backup', 'data_exposure']
                })
            
            # Check for exported components
            if 'exported="true"' in manifest_str:
                vulnerabilities.append({
                    'type': 'Exported Android Components',
                    'severity': 'Medium',
                    'description': 'Application has exported components accessible by other apps',
                    'evidence': 'android:exported="true" found in manifest',
                    'attack_path': [
                        'Exported components can be accessed by other apps',
                        'Malicious apps can invoke activities/services',
                        'Potential for data leakage or unauthorized actions'
                    ],
                    'remediation': [
                        'Set exported="false" for all unnecessary components',
                        'Implement permission checks for exported components',
                        'Use signature-level permissions for sensitive components',
                        'Validate all inputs to exported components'
                    ],
                    'tags': ['android', 'components', 'access_control']
                })
        
        except Exception as e:
            pass
        
        return vulnerabilities
    
    def _find_hardcoded_secrets(self, extract_dir):
        """Find hardcoded secrets in APK"""
        vulnerabilities = []
        secrets_found = {
            'api_keys': [],
            'aws_keys': [],
            'tokens': [],
            'database_urls': [],
            'firebase': [],
            'passwords': [],
        }
        
        # Search in common locations
        search_paths = [
            Path(extract_dir) / "res" / "values",
            Path(extract_dir) / "assets",
            Path(extract_dir) / "resources.arsc",
        ]
        
        for search_path in search_paths:
            if not search_path.exists():
                continue
            
            # Search all files
            if search_path.is_file():
                files = [search_path]
            else:
                files = list(search_path.rglob('*'))
            
            for file_path in files:
                if not file_path.is_file():
                    continue
                
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                    
                    # Search for secrets
                    for secret_type, patterns in self.secret_patterns.items():
                        if secret_type not in secrets_found:
                            secrets_found[secret_type] = []
                        
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
        
        # Create vulnerabilities for found secrets
        if secrets_found['api_keys']:
            vulnerabilities.append({
                'type': 'Hardcoded API Keys in APK',
                'severity': 'Critical',
                'description': 'API keys found hardcoded in Android application',
                'evidence': f'Found {len(secrets_found["api_keys"])} API keys',
                'secrets': secrets_found['api_keys'][:5],  # First 5
                'attack_path': [
                    'Decompile APK to extract resources',
                    'Extract hardcoded API keys',
                    'Use keys to access backend services',
                    'Potentially access/modify data or exhaust quotas'
                ],
                'remediation': [
                    'Never hardcode API keys in mobile apps',
                    'Use backend proxy for API calls',
                    'Implement certificate pinning',
                    'Use dynamic key retrieval from secure backend',
                    'Obfuscate critical strings'
                ],
                'tags': ['android', 'hardcoded_secrets', 'critical']
            })
        
        if secrets_found['aws_keys']:
            vulnerabilities.append({
                'type': 'Hardcoded AWS Credentials',
                'severity': 'Critical',
                'description': 'AWS credentials found hardcoded in Android application',
                'evidence': f'Found {len(secrets_found["aws_keys"])} AWS credentials',
                'secrets': secrets_found['aws_keys'][:3],
                'attack_path': [
                    'Extract AWS credentials from APK',
                    'Use credentials to access AWS resources',
                    'Potentially access S3 buckets, databases, etc.',
                    'Complete infrastructure compromise'
                ],
                'remediation': [
                    'NEVER hardcode AWS credentials',
                    'Use AWS Cognito for mobile authentication',
                    'Implement temporary credentials',
                    'Use IAM roles with minimal permissions',
                    'Rotate credentials immediately if exposed'
                ],
                'tags': ['android', 'aws', 'critical', 'credentials']
            })
        
        if secrets_found['database_urls']:
            vulnerabilities.append({
                'type': 'Hardcoded Database URLs',
                'severity': 'High',
                'description': 'Database connection strings found in APK',
                'evidence': f'Found {len(secrets_found["database_urls"])} database URLs',
                'secrets': secrets_found['database_urls'][:3],
                'attack_path': [
                    'Extract database URLs from APK',
                    'Attempt direct database connections',
                    'Bypass application logic',
                    'Access/modify sensitive data'
                ],
                'remediation': [
                    'Never expose database URLs in mobile apps',
                    'Use backend API as proxy',
                    'Implement proper authentication',
                    'Use VPN/private networks for database access',
                    'Encrypt connection strings if absolutely necessary'
                ],
                'tags': ['android', 'database', 'hardcoded_secrets']
            })
        
        if secrets_found['firebase']:
            vulnerabilities.append({
                'type': 'Firebase Configuration Exposed',
                'severity': 'High',
                'description': 'Firebase configuration found in APK',
                'evidence': f'Found {len(secrets_found["firebase"])} Firebase references',
                'attack_path': [
                    'Extract Firebase configuration',
                    'Access Firebase database directly',
                    'Check for misconfigured security rules',
                    'Read/write data if rules are permissive'
                ],
                'remediation': [
                    'Implement proper Firebase security rules',
                    'Use Firebase Authentication',
                    'Restrict database access by auth status',
                    'Monitor Firebase access logs',
                    'Use Firebase App Check'
                ],
                'tags': ['android', 'firebase', 'configuration']
            })
        
        return vulnerabilities
    
    def _find_api_endpoints(self, extract_dir):
        """Find API endpoints in APK"""
        endpoints = []
        
        # Search for URLs in resources
        search_paths = [
            Path(extract_dir) / "res",
            Path(extract_dir) / "assets",
        ]
        
        for search_path in search_paths:
            if not search_path.exists():
                continue
            
            for file_path in search_path.rglob('*'):
                if not file_path.is_file():
                    continue
                
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                    
                    # Find URLs
                    url_pattern = r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s"\'<>]*)?'
                    matches = re.findall(url_pattern, content)
                    endpoints.extend(matches)
                except:
                    continue
        
        if endpoints:
            unique_endpoints = list(set(endpoints))
            return [{
                'type': 'API Endpoints Discovered',
                'severity': 'Info',
                'description': 'API endpoints found in Android application',
                'evidence': f'Found {len(unique_endpoints)} unique endpoints',
                'endpoints': unique_endpoints[:20],  # First 20
                'attack_path': [
                    'Extract API endpoints from APK',
                    'Test endpoints for vulnerabilities',
                    'Reverse engineer API structure',
                    'Find unauthenticated or vulnerable endpoints'
                ],
                'remediation': [
                    'Implement proper API authentication',
                    'Use API rate limiting',
                    'Validate all API inputs',
                    'Monitor API usage for anomalies',
                    'Consider API obfuscation'
                ],
                'tags': ['android', 'api', 'reconnaissance']
            }]
        
        return []
    
    def _check_debug_mode(self, extract_dir):
        """Check for debug mode indicators"""
        # This is checked in manifest, but also look for other indicators
        return []
    
    def _check_ssl_pinning(self, extract_dir):
        """Check for SSL certificate pinning implementation"""
        vulnerabilities = []
        
        # Search for SSL/TLS related code
        has_pinning = False
        
        search_paths = [Path(extract_dir)]
        
        for search_path in search_paths:
            if not search_path.exists():
                continue
            
            for file_path in search_path.rglob('*'):
                if not file_path.is_file():
                    continue
                
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                    
                    # Look for certificate pinning indicators
                    pinning_patterns = [
                        'CertificatePinner',
                        'TrustManager',
                        'X509TrustManager',
                        'checkServerTrusted',
                        'pinnedCertificates',
                    ]
                    
                    for pattern in pinning_patterns:
                        if pattern in content:
                            has_pinning = True
                            break
                    
                    if has_pinning:
                        break
                except:
                    continue
            
            if has_pinning:
                break
        
        if not has_pinning:
            vulnerabilities.append({
                'type': 'Missing SSL Certificate Pinning',
                'severity': 'Medium',
                'description': 'Application does not implement SSL certificate pinning',
                'evidence': 'No certificate pinning implementation detected',
                'attack_path': [
                    'Attacker performs man-in-the-middle attack',
                    'Installs rogue CA certificate on device',
                    'Intercepts all HTTPS traffic',
                    'Reads/modifies sensitive data in transit'
                ],
                'remediation': [
                    'Implement SSL certificate pinning',
                    'Use network security configuration',
                    'Pin to specific certificates or public keys',
                    'Implement certificate backup pins',
                    'Monitor for pinning failures'
                ],
                'tags': ['android', 'ssl', 'mitm']
            })
        
        return vulnerabilities
    
    def _save_results(self, vulnerabilities):
        """Save APK analysis results"""
        apk_dir = self.workspace / "apk_analysis"
        apk_dir.mkdir(exist_ok=True)
        
        output_file = apk_dir / "apk_vulnerabilities.json"
        with open(output_file, 'w') as f:
            json.dump({
                'target': self.target,
                'apks_analyzed': len(self.apk_urls),
                'vulnerabilities': vulnerabilities
            }, f, indent=2)
