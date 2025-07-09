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
    raw_evidence: Optional[Dict[str, Any]] = None


class BaseSecurityChecks(ABC):
    """Base class for AWS service security checks."""
    
    def __init__(self, aws_client: AWSClientManager):
        self.aws_client = aws_client
        self.logger = logging.getLogger(__name__)
        self.current_region = None
    
    @abstractmethod
    def run_all_checks(self, resources: List[Any], config_checks: Dict[str, CheckConfig], region: str = None) -> List[CheckResult]:
        """Run all security checks for the service."""
        pass
    
    def set_region(self, region: str) -> None:
        """Set the current region for check execution."""
        self.current_region = region
    
    def create_error_result(self, check_id: str, name: str, severity: Severity, 
                          resource_id: str, error: Exception, region: Optional[str] = None,
                          raw_evidence: Optional[Dict[str, Any]] = None) -> CheckResult:
        """Create standardized error result with enhanced details."""
        from botocore.exceptions import ClientError, NoCredentialsError
        
        error_type = type(error).__name__
        error_message = str(error)
        
        # Enhanced error categorization and troubleshooting
        if isinstance(error, ClientError):
            error_code = error.response.get('Error', {}).get('Code', 'Unknown')
            error_msg = error.response.get('Error', {}).get('Message', error_message)
            
            # Create detailed evidence
            evidence = f"AWS API Error: {error_code} - {error_msg}"
            
            # Enhanced raw evidence for ClientError
            if raw_evidence is None:
                raw_evidence = {
                    'error_type': error_type,
                    'error_code': error_code,
                    'error_message': error_msg,
                    'response_metadata': error.response.get('ResponseMetadata', {}),
                    'operation_name': error.operation_name if hasattr(error, 'operation_name') else None
                }
            
            # Provide specific troubleshooting based on error code
            if error_code == 'AccessDenied':
                remediation = "Check IAM permissions for the required actions on this resource"
            elif error_code == 'UnauthorizedOperation':
                remediation = "Verify IAM policy allows the required operation"
            elif error_code == 'InvalidUserID.NotFound':
                remediation = "Check if the resource exists and user has access"
            elif error_code == 'Throttling':
                remediation = "Reduce request rate or implement exponential backoff"
            elif error_code == 'ServiceUnavailable':
                remediation = "AWS service may be experiencing issues, retry later"
            else:
                remediation = f"Review AWS documentation for error code: {error_code}"
                
        elif isinstance(error, NoCredentialsError):
            evidence = "AWS credentials not found or invalid"
            remediation = "Configure AWS credentials using AWS CLI, environment variables, or IAM roles"
            raw_evidence = raw_evidence or {
                'error_type': error_type,
                'error_message': error_message,
                'troubleshooting': 'Check AWS credential configuration'
            }
        else:
            evidence = f"{error_type}: {error_message}"
            remediation = "Check resource permissions, network connectivity, and retry"
            raw_evidence = raw_evidence or {
                'error_type': error_type,
                'error_message': error_message,
                'full_traceback': str(error)
            }
        
        return CheckResult(
            check_id=check_id,
            name=name,
            status=CheckStatus.ERROR,
            severity=severity,
            description=f"Error checking {name.lower()}",
            evidence=evidence,
            remediation=remediation,
            resource_id=resource_id,
            region=region,
            raw_evidence=raw_evidence
        )