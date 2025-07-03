"""Base classes for security checks."""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
from abc import ABC, abstractmethod

from ..aws_client import AWSClientManager
from ..config_manager import CheckConfig, Severity


class CheckStatus(Enum):
    """Security check result status."""
    OK = "OK"
    NOK = "NOK"
    NEED_REVIEW = "NEED_REVIEW"
    ERROR = "ERROR"


@dataclass
class CheckResult:
    """Result of a security check."""
    check_id: str
    name: str
    status: CheckStatus
    severity: Severity
    description: str
    evidence: str
    remediation: Optional[str] = None
    resource_id: Optional[str] = None
    region: Optional[str] = None


class BaseSecurityChecks(ABC):
    """Base class for AWS service security checks."""
    
    def __init__(self, aws_client: AWSClientManager):
        self.aws_client = aws_client
        self.logger = logging.getLogger(__name__)
    
    @abstractmethod
    def run_all_checks(self, resources: List[Any], config_checks: Dict[str, CheckConfig]) -> List[CheckResult]:
        """Run all security checks for the service."""
        pass
    
    def create_error_result(self, check_id: str, name: str, severity: Severity, 
                          resource_id: str, error: Exception) -> CheckResult:
        """Create standardized error result."""
        return CheckResult(
            check_id=check_id,
            name=name,
            status=CheckStatus.ERROR,
            severity=severity,
            description=f"Error checking {name.lower()}",
            evidence=f"Error: {str(error)}",
            remediation="Check resource permissions and retry",
            resource_id=resource_id
        )