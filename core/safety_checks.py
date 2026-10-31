#!/usr/bin/env python3
"""
REVUEX - Safety Checks
Validation and safety enforcement for all scanners.

Author: G33L0
Telegram: @x0x0h33l0

NOTE (v2.1): the previous copy of this file contained markdown-export artifacts
(code fences and smart quotes) and did not parse. This is a faithful, clean
rewrite of the same API and logic so the module is importable and usable.
"""

import re
import socket
import ipaddress
from typing import Optional, Tuple
from urllib.parse import urlparse


class SafetyValidator:
    """Multi-layer safety validation system.

    Prevents: testing production systems without authorization, destructive
    operations, rate-limit violations, and dangerous payloads.
    """

    # RFC1918 / link-local / loopback ranges.
    PRIVATE_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),
        ipaddress.ip_network('::1/128'),
        ipaddress.ip_network('fe80::/10'),
    ]

    # Cloud metadata endpoints (DO NOT ATTACK).
    CLOUD_METADATA_IPS = [
        '169.254.169.254',        # AWS, GCP, Azure
        '169.254.169.253',        # AWS IMDSv2
        'metadata.google.internal',
        '100.100.100.200',        # Alibaba Cloud
    ]

    # Destructive operation keywords.
    DESTRUCTIVE_KEYWORDS = [
        'DROP', 'DELETE', 'TRUNCATE', 'ALTER', 'CREATE',
        'INSERT', 'UPDATE', 'EXEC', 'EXECUTE', 'SHUTDOWN',
        'REBOOT', 'TERMINATE', 'DESTROY', 'REMOVE', 'KILL',
    ]

    @staticmethod
    def is_valid_target(url: str) -> Tuple[bool, Optional[str]]:
        """Validate target URL is safe to test. Returns (is_valid, error)."""
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ('http', 'https'):
                return False, f"Invalid scheme: {parsed.scheme}"

            hostname = parsed.netloc.split(':')[0]
            if hostname.lower() in ('localhost', '127.0.0.1', '0.0.0.0', '::1'):
                return False, "Localhost testing not allowed"

            if hostname in SafetyValidator.CLOUD_METADATA_IPS:
                return False, "Cloud metadata endpoint detected - FORBIDDEN"

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
        """Validate a payload does not contain destructive operations."""
        payload_upper = (payload or "").upper()
        for keyword in SafetyValidator.DESTRUCTIVE_KEYWORDS:
            if keyword in payload_upper:
                return False, f"Destructive keyword detected: {keyword}"
        return True, None

    @staticmethod
    def validate_sql_payload(payload: str) -> Tuple[bool, Optional[str]]:
        """Validate a SQL payload is read-only."""
        payload_upper = (payload or "").upper()
        safe_operations = ['SELECT', 'SHOW', 'DESCRIBE', 'EXPLAIN']
        has_safe_op = any(op in payload_upper for op in safe_operations)
        dangerous_ops = ['DROP', 'DELETE', 'INSERT', 'UPDATE', 'ALTER',
                         'CREATE', 'TRUNCATE', 'EXEC', 'EXECUTE']
        if any(op in payload_upper for op in dangerous_ops):
            return False, "SQL payload contains write/destructive operations"
        if not has_safe_op:
            return False, "SQL payload must contain SELECT or read operation"
        return True, None

    @staticmethod
    def check_rate_limit(request_count: int, max_requests: int,
                         elapsed_time: float, min_delay: float) -> Tuple[bool, Optional[str]]:
        """Check if rate limits are being respected."""
        if request_count >= max_requests:
            return False, f"Request limit exceeded: {request_count}/{max_requests}"
        if elapsed_time > 0 and min_delay > 0:
            rate = request_count / elapsed_time
            max_rate = 1.0 / min_delay
            if rate > max_rate:
                return False, f"Rate limit exceeded: {rate:.2f} req/s (max: {max_rate:.2f})"
        return True, None

    @staticmethod
    def validate_file_upload(filename: str, content: bytes,
                             max_size: int = 1024 * 1024) -> Tuple[bool, Optional[str]]:
        """Validate a test file upload is safe."""
        if len(content) > max_size:
            return False, f"File too large: {len(content)} bytes (max: {max_size})"
        dangerous_extensions = ['.exe', '.dll', '.so', '.dylib', '.bin']
        if any(filename.lower().endswith(ext) for ext in dangerous_extensions):
            return False, "Dangerous file extension detected"
        magic_bytes = [b'MZ', b'\x7fELF', b'\xfe\xed\xfa']
        for magic in magic_bytes:
            if content.startswith(magic):
                return False, "Executable file detected"
        return True, None

    @staticmethod
    def is_test_environment(url: str) -> bool:
        """Heuristic: does the URL look like a test/staging environment?"""
        test_indicators = ['test', 'staging', 'dev', 'development', 'qa',
                           'sandbox', 'demo', 'local', 'preview', 'beta', 'alpha']
        url_lower = (url or "").lower()
        return any(ind in url_lower for ind in test_indicators)

    @staticmethod
    def validate_session_token(token: str) -> Tuple[bool, Optional[str]]:
        """Validate a session token has sufficient entropy."""
        if not token:
            return False, "Empty token"
        if len(token) < 16:
            return False, f"Token too short: {len(token)} chars (min: 16)"
        unique_chars = len(set(token))
        entropy_ratio = unique_chars / len(token)
        if entropy_ratio < 0.3:
            return False, f"Low token entropy: {entropy_ratio:.2%}"
        if token.isdigit():
            return False, "Token is all numeric (weak)"
        return True, None

    @staticmethod
    def sanitize_output(data: str, max_length: int = 1000) -> str:
        """Sanitize output data to prevent log injection."""
        sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', data or "")
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + '...[truncated]'
        return sanitized

    @staticmethod
    def get_safety_profile(scanner_name: str) -> dict:
        """Get the recommended safety profile for a scanner."""
        profiles = {
            'SSRFScanner': {'max_requests': 50, 'delay': 3.0,
                            'allow_private_ips': False, 'read_only': True,
                            'require_confirmation': True},
            'SQLiScanner': {'max_requests': 100, 'delay': 2.0,
                            'allow_write_ops': False, 'read_only': True,
                            'timeout': 5},
            'FileUploadTester': {'max_requests': 20, 'delay': 5.0,
                                 'max_file_size': 1024 * 1024, 'auto_cleanup': True},
            'RaceConditionTester': {'max_requests': 30, 'delay': 3.0,
                                    'max_threads': 10, 'require_confirmation': True},
            'default': {'max_requests': 100, 'delay': 2.0, 'timeout': 10,
                        'read_only': True},
        }
        return profiles.get(scanner_name, profiles['default'])


class EnvironmentDetector:
    """Detect and classify the target environment."""

    @staticmethod
    def detect_environment(url: str, response_headers: dict = None) -> str:
        """Return 'production' | 'staging' | 'development' | 'test' | 'unknown'."""
        url_lower = (url or "").lower()
        if any(ind in url_lower for ind in ['staging', 'stage', 'stg']):
            return 'staging'
        if any(ind in url_lower for ind in ['dev', 'development']):
            return 'development'
        if any(ind in url_lower for ind in ['test', 'qa', 'sandbox']):
            return 'test'
        if any(ind in url_lower for ind in ['prod', 'www', 'api']):
            return 'production'
        if response_headers:
            server = (response_headers.get('Server', '') or '').lower()
            if 'development' in server or 'debug' in server:
                return 'development'
        return 'unknown'

    @staticmethod
    def should_proceed(environment: str, require_confirmation: bool = True) -> bool:
        """Determine if testing should proceed based on the environment."""
        if environment in ('test', 'development', 'staging'):
            return True
        # Production requires explicit, out-of-band authorization; default deny.
        return False
