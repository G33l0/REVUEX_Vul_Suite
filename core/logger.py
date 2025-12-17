#!/usr/bin/env python3
"""
REVUEX Logger - Advanced Logging System v2.0
Author: G33L0
Telegram: @x0x0h33l0
GitHub: github.com/G33L0/revuex-vul-suite

Enhanced Features:

- Multi-level logging (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- Structured log format with timestamps
- Scanner activity tracking
- Performance metrics
- Audit trail generation
- Color-coded console output
- Rotating log files
- Statistics tracking
  “””

import logging
import json
from pathlib import Path
from datetime import datetime
from logging.handlers import RotatingFileHandler
from collections import defaultdict
import time

class Colors:
RED = ‘\033[91m’
GREEN = ‘\033[92m’
YELLOW = ‘\033[93m’
BLUE = ‘\033[94m’
MAGENTA = ‘\033[95m’
CYAN = ‘\033[96m’
BOLD = ‘\033[1m’
END = ‘\033[0m’

class ColoredFormatter(logging.Formatter):
“”“Custom formatter with color support”””

```
COLORS = {
    'DEBUG': Colors.BLUE,
    'INFO': Colors.CYAN,
    'WARNING': Colors.YELLOW,
    'ERROR': Colors.RED,
    'CRITICAL': Colors.BOLD + Colors.RED,
    'SUCCESS': Colors.GREEN,
    'VULNERABILITY': Colors.MAGENTA,
    'EXPLOIT': Colors.RED + Colors.BOLD,
}

def format(self, record):
    # Add color to levelname
    levelname = record.levelname
    if levelname in self.COLORS:
        record.levelname = f"{self.COLORS[levelname]}{levelname}{Colors.END}"
    return super().format(record)
```

class RevuexLogger:
“”“Advanced logging system for REVUEX Suite v2.0”””

```
def __init__(self, workspace, log_level=logging.INFO):
    """
    Initialize advanced logger
    
    Args:
        workspace: Workspace directory path
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    self.workspace = Path(workspace)
    self.log_file = self.workspace / "revuex_scan.log"
    self.stats_file = self.workspace / "scan_statistics.json"
    self.audit_file = self.workspace / "audit_trail.log"
    
    # Initialize statistics
    self.stats = {
        'start_time': datetime.now().isoformat(),
        'scanners_used': [],
        'vulnerabilities_found': 0,
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0,
        'requests_made': 0,
        'errors': 0,
        'warnings': 0,
        'scanner_timings': {},
        'phase_timings': {}
    }
    
    # Scanner activity tracking
    self.scanner_activity = defaultdict(lambda: {
        'started': None,
        'completed': None,
        'duration': None,
        'findings': 0,
        'requests': 0,
        'errors': 0
    })
    
    # Performance metrics
    self.performance = {
        'phase_start_times': {},
        'scanner_start_times': {}
    }
    
    # Setup loggers
    self._setup_main_logger(log_level)
    self._setup_audit_logger()
    
    self.log_info(f"REVUEX Logger v2.0 initialized")
    self.log_info(f"Log file: {self.log_file}")

def _setup_main_logger(self, log_level):
    """Setup main logger with rotating file handler"""
    self.logger = logging.getLogger('REVUEX')
    self.logger.setLevel(log_level)
    
    # Remove existing handlers
    self.logger.handlers = []
    
    # File handler with rotation (max 10MB, keep 5 backups)
    file_handler = RotatingFileHandler(
        self.log_file,
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(log_level)
    file_formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    
    # Console handler with colors
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_formatter = ColoredFormatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    
    self.logger.addHandler(file_handler)
    self.logger.addHandler(console_handler)

def _setup_audit_logger(self):
    """Setup separate audit trail logger"""
    self.audit_logger = logging.getLogger('REVUEX.AUDIT')
    self.audit_logger.setLevel(logging.INFO)
    
    # Remove existing handlers
    self.audit_logger.handlers = []
    
    audit_handler = RotatingFileHandler(
        self.audit_file,
        maxBytes=10*1024*1024,
        backupCount=3
    )
    audit_formatter = logging.Formatter(
        '%(asctime)s [AUDIT] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    audit_handler.setFormatter(audit_formatter)
    self.audit_logger.addHandler(audit_handler)

# ========================================
# BASIC LOGGING METHODS
# ========================================

def log_debug(self, message):
    """Log debug message"""
    self.logger.debug(message)

def log_info(self, message):
    """Log info message"""
    self.logger.info(message)

def log_success(self, message):
    """Log success message"""
    self.logger.info(f"{Colors.GREEN}[SUCCESS]{Colors.END} {message}")
    self.audit_logger.info(f"SUCCESS: {message}")

def log_warning(self, message):
    """Log warning message"""
    self.logger.warning(message)
    self.stats['warnings'] += 1

def log_error(self, message):
    """Log error message"""
    self.logger.error(message)
    self.stats['errors'] += 1
    self.audit_logger.info(f"ERROR: {message}")

def log_critical(self, message):
    """Log critical message"""
    self.logger.critical(message)
    self.stats['errors'] += 1
    self.audit_logger.info(f"CRITICAL: {message}")

# ========================================
# SCANNER ACTIVITY TRACKING
# ========================================

def log_scanner_start(self, scanner_name, target):
    """Log scanner start"""
    self.scanner_activity[scanner_name]['started'] = datetime.now()
    self.performance['scanner_start_times'][scanner_name] = time.time()
    
    if scanner_name not in self.stats['scanners_used']:
        self.stats['scanners_used'].append(scanner_name)
    
    self.logger.info(f"{Colors.CYAN}[SCANNER START]{Colors.END} {scanner_name} on {target}")
    self.audit_logger.info(f"SCANNER_START: {scanner_name} | Target: {target}")

def log_scanner_complete(self, scanner_name, findings_count=0):
    """Log scanner completion"""
    activity = self.scanner_activity[scanner_name]
    activity['completed'] = datetime.now()
    activity['findings'] = findings_count
    
    # Calculate duration
    if scanner_name in self.performance['scanner_start_times']:
        start_time = self.performance['scanner_start_times'][scanner_name]
        duration = time.time() - start_time
        activity['duration'] = duration
        self.stats['scanner_timings'][scanner_name] = duration
    
    self.logger.info(
        f"{Colors.GREEN}[SCANNER COMPLETE]{Colors.END} {scanner_name} - "
        f"{findings_count} findings in {activity['duration']:.2f}s"
    )
    self.audit_logger.info(
        f"SCANNER_COMPLETE: {scanner_name} | Findings: {findings_count} | "
        f"Duration: {activity['duration']:.2f}s"
    )

def log_scanner_error(self, scanner_name, error_message):
    """Log scanner error"""
    self.scanner_activity[scanner_name]['errors'] += 1
    self.logger.error(f"[{scanner_name}] {error_message}")
    self.audit_logger.info(f"SCANNER_ERROR: {scanner_name} | Error: {error_message}")

# ========================================
# PHASE TRACKING
# ========================================

def log_phase_start(self, phase_name):
    """Log phase start"""
    self.performance['phase_start_times'][phase_name] = time.time()
    self.logger.info(f"{Colors.BOLD}{Colors.CYAN}[PHASE START]{Colors.END} {phase_name}")
    self.audit_logger.info(f"PHASE_START: {phase_name}")

def log_phase_complete(self, phase_name, summary=""):
    """Log phase completion"""
    if phase_name in self.performance['phase_start_times']:
        start_time = self.performance['phase_start_times'][phase_name]
        duration = time.time() - start_time
        self.stats['phase_timings'][phase_name] = duration
        
        self.logger.info(
            f"{Colors.BOLD}{Colors.GREEN}[PHASE COMPLETE]{Colors.END} {phase_name} - "
            f"{duration:.2f}s {summary}"
        )
        self.audit_logger.info(
            f"PHASE_COMPLETE: {phase_name} | Duration: {duration:.2f}s | {summary}"
        )

# ========================================
# VULNERABILITY LOGGING
# ========================================

def log_vulnerability(self, vuln_type, severity, target, scanner=None):
    """
    Log vulnerability discovery
    
    Args:
        vuln_type: Type of vulnerability (e.g., "SQL Injection")
        severity: Severity level (critical, high, medium, low, info)
        target: Target URL or endpoint
        scanner: Name of scanner that found it
    """
    severity_lower = severity.lower()
    if severity_lower in ['critical', 'high', 'medium', 'low', 'info']:
        self.stats[severity_lower] += 1
    self.stats['vulnerabilities_found'] += 1
    
    severity_colors = {
        'critical': Colors.RED + Colors.BOLD,
        'high': Colors.RED,
        'medium': Colors.YELLOW,
        'low': Colors.GREEN,
        'info': Colors.CYAN
    }
    
    color = severity_colors.get(severity_lower, Colors.CYAN)
    scanner_info = f" by {scanner}" if scanner else ""
    
    self.logger.info(
        f"{color}[VULNERABILITY]{Colors.END} {severity.upper()} - {vuln_type} "
        f"on {target}{scanner_info}"
    )
    self.audit_logger.info(
        f"VULNERABILITY: {severity.upper()} | Type: {vuln_type} | "
        f"Target: {target} | Scanner: {scanner or 'Unknown'}"
    )

def log_vulnerability_detail(self, vuln_data):
    """
    Log detailed vulnerability information
    
    Args:
        vuln_data: Dictionary containing vulnerability details
    """
    vuln_json = json.dumps(vuln_data, indent=2)
    self.logger.debug(f"Vulnerability Detail: {vuln_json}")
    self.audit_logger.info(f"VULNERABILITY_DETAIL: {vuln_json}")

# ========================================
# EXPLOITATION LOGGING
# ========================================

def log_exploit_start(self, exploit_type, target):
    """Log exploitation attempt start"""
    self.logger.info(
        f"{Colors.YELLOW}[EXPLOIT START]{Colors.END} {exploit_type} on {target}"
    )
    self.audit_logger.info(f"EXPLOIT_START: {exploit_type} | Target: {target}")

def log_exploit(self, exploit_type, target, success, details=""):
    """
    Log exploitation attempt
    
    Args:
        exploit_type: Type of exploit
        target: Target URL or endpoint
        success: Boolean indicating success
        details: Additional details
    """
    status = "SUCCESS" if success else "FAILED"
    color = Colors.RED + Colors.BOLD if success else Colors.YELLOW
    
    self.logger.info(
        f"{color}[EXPLOIT {status}]{Colors.END} {exploit_type} on {target} {details}"
    )
    self.audit_logger.info(
        f"EXPLOIT: {status} | Type: {exploit_type} | Target: {target} | "
        f"Details: {details}"
    )

# ========================================
# REQUEST TRACKING
# ========================================

def log_request(self, method, url, status_code=None, response_time=None):
    """Log HTTP request"""
    self.stats['requests_made'] += 1
    
    details = []
    if status_code:
        details.append(f"Status: {status_code}")
    if response_time:
        details.append(f"Time: {response_time:.2f}s")
    
    detail_str = " | ".join(details) if details else ""
    self.logger.debug(f"[REQUEST] {method} {url} {detail_str}")

def log_requests_count(self, scanner_name, count):
    """Log number of requests made by scanner"""
    self.scanner_activity[scanner_name]['requests'] = count
    self.stats['requests_made'] += count

# ========================================
# STATISTICS & REPORTING
# ========================================

def save_statistics(self):
    """Save scan statistics to file"""
    self.stats['end_time'] = datetime.now().isoformat()
    
    # Calculate total duration
    start_time = datetime.fromisoformat(self.stats['start_time'])
    end_time = datetime.fromisoformat(self.stats['end_time'])
    self.stats['total_duration'] = str(end_time - start_time)
    
    # Add scanner activity
    self.stats['scanner_activity'] = {
        name: {
            'started': str(data['started']) if data['started'] else None,
            'completed': str(data['completed']) if data['completed'] else None,
            'duration': data['duration'],
            'findings': data['findings'],
            'requests': data['requests'],
            'errors': data['errors']
        }
        for name, data in self.scanner_activity.items()
    }
    
    with open(self.stats_file, 'w') as f:
        json.dump(self.stats, f, indent=2)
    
    self.logger.info(f"Statistics saved to {self.stats_file}")

def get_statistics(self):
    """Get current scan statistics"""
    return self.stats.copy()

def print_summary(self):
    """Print scan summary"""
    summary = f"""
```

{Colors.BOLD}{Colors.CYAN}╔════════════════════════════════════════════╗{Colors.END}
{Colors.BOLD}{Colors.CYAN}║         SCAN SUMMARY                       ║{Colors.END}
{Colors.BOLD}{Colors.CYAN}╚════════════════════════════════════════════╝{Colors.END}

{Colors.CYAN}Scanners Used:{Colors.END} {len(self.stats[‘scanners_used’])}
{Colors.CYAN}Total Requests:{Colors.END} {self.stats[‘requests_made’]}
{Colors.CYAN}Vulnerabilities Found:{Colors.END} {self.stats[‘vulnerabilities_found’]}
{Colors.RED}Critical:{Colors.END} {self.stats[‘critical’]}
{Colors.RED}High:{Colors.END} {self.stats[‘high’]}
{Colors.YELLOW}Medium:{Colors.END} {self.stats[‘medium’]}
{Colors.GREEN}Low:{Colors.END} {self.stats[‘low’]}
{Colors.CYAN}Info:{Colors.END} {self.stats[‘info’]}

{Colors.CYAN}Errors:{Colors.END} {self.stats[‘errors’]}
{Colors.CYAN}Warnings:{Colors.END} {self.stats[‘warnings’]}
“””
print(summary)
self.logger.info(“Scan summary printed”)

```
# ========================================
# FILE ACCESS
# ========================================

def get_log_file(self):
    """Get log file path"""
    return self.log_file

def get_audit_file(self):
    """Get audit trail file path"""
    return self.audit_file

def get_stats_file(self):
    """Get statistics file path"""
    return self.stats_file
```