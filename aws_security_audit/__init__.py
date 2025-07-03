"""
AWS Security Audit Tool

A comprehensive security audit tool for AWS accounts that generates detailed 
compliance reports with exportable formats for auditor review.
"""

__version__ = "1.0.0"
__author__ = "Security Compliance Team"
__email__ = "security@example.com"
__license__ = "MIT"

# Main exports for public API
from .aws_client import AWSClientManager
from .config_manager import ConfigManager, SecurityProfile, Severity
from .security_engine import SecurityEngine
from .checks.base_checks import CheckResult, CheckStatus
from .reports.report_generator import ReportGenerator

__all__ = [
    "AWSClientManager",
    "ConfigManager", 
    "SecurityProfile",
    "Severity",
    "SecurityEngine",
    "CheckResult",
    "CheckStatus", 
    "ReportGenerator",
    "__version__",
    "__author__",
    "__email__",
    "__license__",
]