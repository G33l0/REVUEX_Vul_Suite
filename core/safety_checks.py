#!/usr/bin/env python3
“””
REVUEX - Safety Checks
Validation and safety enforcement for all scanners

Author: G33L0
Telegram: @x0x0h33l0
“””

import re
import socket
from typing import List, Optional, Tuple
from urllib.parse import urlparse
import ipaddress

class SafetyValidator:
“””
Multi-layer safety validation system

```
Prevents:
- Testing production systems without authorization
- Destructive operations
- Rate limit violations
- Dangerous payloads
"""

# RFC1918 private address ranges
PRIVATE_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fe80::/10'),
]

# Cloud metadata endpoints (DO NOT ATTACK)
CLOUD_METADATA_IPS = [
    '169.254.169.254',  # AWS, GCP, Azure
    '169.254.169.253',  # AWS IMDSv2
    'metadata.google.internal',
    '100.100.100.200',  # Alibaba Cloud
]

# Dangerous operations keywords
DESTRUCTIVE_KEYWORDS = [
    'DROP', 'DELETE', 'TRUNCATE', 'ALTER', 'CREATE',
    'INSERT', 'UPDATE', 'EXEC', 'EXECUTE', 'SHUTDOWN',
    'REBOOT', 'TERMINATE', 'DESTROY', 'REMOVE', 'KILL'
]

@staticmethod
def is_valid_target(url: str) -> Tuple[bool, Optional[str]]:
    """
    Validate target URL is safe to test
    
    Args:
        url: Target URL
        
    Returns:
        (is_valid, error_message)
    """
    try:
        parsed = urlparse(url)
        
        # Check scheme
        if parsed.scheme not in ['http', 'https']:
            return False, f"Invalid scheme: {parsed.scheme}"
        
        # Extract hostname
        hostname = parsed.netloc.split(':')[0]
        
        # Check for localhost
        if hostname.lower() in ['localhost', '127.0.0.1', '0.0.0.0', '::1']:
            return False, "Localhost testing not allowed"
        
        # Check for cloud metadata
        if hostname in SafetyValidator.CLOUD_METADATA_IPS:
            return False, "Cloud metadata endpoint detected - FORBIDDEN"
        
        # Check if it resolves to private IP
        try:
            ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip)
            
            for private_range in SafetyValidator.PRIVATE_RANGES:
                if ip_obj in private_range:
                    return False, f"Private IP range detected: {ip}"
        except socket.gaierror:
            return False, f"Cannot resolve hostname: {hostname}"
        
        return True, None
        
    except Exception as e:
        return False, f"URL validation error: {str(e)}"

@staticmethod
def is_safe_payload(payload: str) -> Tuple[bool, Optional[str]]:
    """
    Validate payload doesn't contain destructive operations
    
    Args:
        payload: Payload string to validate
        
    Returns:
        (is_safe, warning_message)
    """
    payload_upper = payload.upper()
    
    for keyword in SafetyValidator.DESTRUCTIVE_KEYWORDS:
        if keyword in payload_upper:
            return False, f"Destructive keyword detected: {keyword}"
    
    return True, None

@staticmethod
def validate_sql_payload(payload: str) -> Tuple[bool, Optional[str]]:
    """
    Validate SQL payload is read-only
    
    Args:
        payload: SQL payload
        
    Returns:
        (is_valid, error_message)
    """
    payload_upper = payload.upper()
    
    # Check for SELECT or similar read operations
    safe_operations = ['SELECT', 'SHOW', 'DESCRIBE', 'EXPLAIN']
    has_safe_op = any(op in payload_upper for op in safe_operations)
    
    # Check for dangerous operations
    dangerous_ops = [
        'DROP', 'DELETE', 'INSERT', 'UPDATE', 'ALTER',
        'CREATE', 'TRUNCATE', 'EXEC', 'EXECUTE'
    ]
    has_dangerous_op = any(op in payload_upper for op in dangerous_ops)
    
    if has_dangerous_op:
        return False, "SQL payload contains write/destructive operations"
    
    if not has_safe_op:
        return False, "SQL payload must contain SELECT or read operation"
    
    return True, None

@staticmethod
def check_rate_limit(request_count: int, max_requests: int, 
                    elapsed_time: float, min_delay: float) -> Tuple[bool, Optional[str]]:
    """
    Check if rate limits are being respected
    
    Args:
        request_count: Number of requests made
        max_requests: Maximum allowed requests
        elapsed_time: Time elapsed since start
        min_delay: Minimum delay between requests
        
    Returns:
        (is_compliant, warning_message)
    """
    # Check total request limit
    if request_count >= max_requests:
        return False, f"Request limit exceeded: {request_count}/{max_requests}"
    
    # Check rate (requests per second)
    if elapsed_time > 0:
        rate = request_count / elapsed_time
        max_rate = 1.0 / min_delay
        
        if rate > max_rate:
            return False, f"Rate limit exceeded: {rate:.2f} req/s (max: {max_rate:.2f})"
    
    return True, None

@staticmethod
def validate_file_upload(filename: str, content: bytes, max_size: int = 1024*1024) -> Tuple[bool, Optional[str]]:
    """
    Validate file upload is safe for testing
    
    Args:
        filename: Uploaded filename
        content: File content
        max_size: Maximum file size in bytes
        
    Returns:
        (is_safe, warning_message)
    """
    # Check file size
    if len(content) > max_size:
        return False, f"File too large: {len(content)} bytes (max: {max_size})"
    
    # Check for dangerous extensions in test mode
    dangerous_extensions = ['.exe', '.dll', '.so', '.dylib', '.bin']
    
    if any(filename.lower().endswith(ext) for ext in dangerous_extensions):
        return False, f"Dangerous file extension detected"
    
    # Check for executable magic bytes
    magic_bytes = [
        b'MZ',      # Windows executable
        b'\x7fELF', # Linux executable
        b'\xfe\xed\xfa',  # Mach-O
    ]
    
    for magic in magic_bytes:
        if content.startswith(magic):
            return False, "Executable file detected"
    
    return True, None

@staticmethod
def is_test_environment(url: str) -> bool:
    """
    Detect if URL appears to be test/staging environment
    
    Args:
        url: Target URL
        
    Returns:
        True if appears to be test environment
    """
    test_indicators = [
        'test', 'staging', 'dev', 'development',
        'qa', 'sandbox', 'demo', 'local',
        'preview', 'beta', 'alpha'
    ]
    
    url_lower = url.lower()
    
    return any(indicator in url_lower for indicator in test_indicators)

@staticmethod
def validate_session_token(token: str) -> Tuple[bool, Optional[str]]:
    """
    Validate session token has sufficient entropy
    
    Args:
        token: Session token
        
    Returns:
        (is_secure, warning_message)
    """
    if not token:
        return False, "Empty token"
    
    # Check minimum length
    if len(token) < 16:
        return False, f"Token too short: {len(token)} chars (min: 16)"
    
    # Calculate entropy (simple check)
    unique_chars = len(set(token))
    entropy_ratio = unique_chars / len(token)
    
    if entropy_ratio < 0.3:
        return False, f"Low token entropy: {entropy_ratio:.2%}"
    
    # Check if token is all numeric (weak)
    if token.isdigit():
        return False, "Token is all numeric (weak)"
    
    return True, None

@staticmethod
def sanitize_output(data: str, max_length: int = 1000) -> str:
    """
    Sanitize output data to prevent log injection
    
    Args:
        data: Data to sanitize
        max_length: Maximum output length
        
    Returns:
        Sanitized string
    """
    # Remove control characters
    sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', data)
    
    # Truncate if too long
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + '...[truncated]'
    
    return sanitized

@staticmethod
def get_safety_profile(scanner_name: str) -> dict:
    """
    Get recommended safety profile for scanner
    
    Args:
        scanner_name: Name of the scanner
        
    Returns:
        Safety profile dictionary
    """
    profiles = {
        'SSRFScanner': {
            'max_requests': 50,
            'delay': 3.0,
            'allow_private_ips': False,
            'read_only': True,
            'require_confirmation': True
        },
        'SQLiScanner': {
            'max_requests': 100,
            'delay': 2.0,
            'allow_write_ops': False,
            'read_only': True,
            'timeout': 5
        },
        'FileUploadTester': {
            'max_requests': 20,
            'delay': 5.0,
            'max_file_size': 1024*1024,
            'auto_cleanup': True
        },
        'RaceConditionTester': {
            'max_requests': 30,
            'delay': 3.0,
            'max_threads': 10,
            'require_confirmation': True
        },
        'default': {
            'max_requests': 100,
            'delay': 2.0,
            'timeout': 10,
            'read_only': True
        }
    }
    
    return profiles.get(scanner_name, profiles['default'])
```

class EnvironmentDetector:
“”“Detect and classify target environment”””

```
@staticmethod
def detect_environment(url: str, response_headers: dict = None) -> str:
    """
    Detect environment type
    
    Args:
        url: Target URL
        response_headers: HTTP response headers
        
    Returns:
        Environment type: 'production', 'staging', 'development', 'test', 'unknown'
    """
    url_lower = url.lower()
    
    # Check URL for indicators
    if any(ind in url_lower for ind in ['prod', 'www', 'api']):
        return 'production'
    
    if any(ind in url_lower for ind in ['staging', 'stage', 'stg']):
        return 'staging'
    
    if any(ind in url_lower for ind in ['dev', 'development']):
        return 'development'
    
    if any(ind in url_lower for ind in ['test', 'qa', 'sandbox']):
        return 'test'
    
    # Check response headers
    if response_headers:
        server = response_headers.get('Server', '').lower()
        
        if 'development' in server or 'debug' in server:
            return 'development'
    
    return 'unknown'

@staticmethod
def should_proceed(environment: str, require_confirmation: bool = True) -> bool:
    """
    Determine if testing should proceed based on environment
    
    Args:
        environment: Detected environment
        require_confirmation: Whether to require user confirmation
        
    Returns:
        True if safe to proceed
    """
    if environment in ['test', 'development', 'staging']:
        return True
    
    if environment == 'production' and require_confirmation:
        # In a real implementation, this would prompt the user
        # For now, return False for safety
        return False
    
    return False
```
