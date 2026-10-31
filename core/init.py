"""
REVUEX Vulnerability Suite - Core Modules
Advanced Bug Bounty Automation Framework v2.0

Author: G33L0
Telegram: @x0x0h33l0
GitHub: github.com/G33L0/revuex-vul-suite

Core Components:
- IntelligenceHub: Central database for recon and vulnerability data
- ReportGenerator: Enterprise-grade HTML report generation
- RevuexLogger: Comprehensive logging and audit trails

NOTE: This file is named ``init.py`` (not ``__init__.py``); ``core`` is used as
a namespace package by the launcher. It is kept as valid, importable Python for
tooling/metadata purposes. Previously it contained markdown-export artifacts
(``**version**``, code fences) that made it fail to parse.
"""

__version__ = "2.0"
__author__ = "G33L0"
__telegram__ = "@x0x0h33l0"
__github__ = "github.com/G33L0/revuex-vul-suite"

__all__ = [
    "IntelligenceHub",
    "ReportGenerator",
    "RevuexLogger",
]

# Version history
VERSION_HISTORY = {
    "2.0": {
        "date": "2024-12-15",
        "changes": [
            "Added advanced security scanners",
            "Enhanced report generator with CVSS scoring",
            "Added compliance mapping (PCI-DSS, GDPR, HIPAA)",
            "Improved intelligence hub with scanner tracking",
            "Enhanced logging with severity levels",
            "Added payload library support",
        ],
    },
    "1.0": {
        "date": "2024-11-01",
        "changes": [
            "Initial release",
            "8 core security scanners",
            "Basic HTML reporting",
            "Sequential execution",
        ],
    },
}


def get_version():
    """Get current REVUEX Core version."""
    return __version__


def get_module_info():
    """Get detailed module information."""
    return {
        "version": __version__,
        "author": __author__,
        "telegram": __telegram__,
        "github": __github__,
        "modules": list(__all__),
    }


version_info = {"major": 2, "minor": 0, "patch": 0, "release": "stable"}
