"""Input validation for AWS Security Audit Tool."""

import re
from typing import Dict, Optional, Any
from dataclasses import dataclass
from enum import Enum


class AuthMethod(Enum):
    """Supported authentication methods."""
    PROFILE = "profile"
    ROLE = "role"
    KEYS = "keys"
    INSTANCE = "instance"


class SecurityProfile(Enum):
    """Supported security profiles."""
    CIS_AWS_FOUNDATIONS = "CIS_AWS_Foundations"
    NIST_CYBERSECURITY = "NIST_Cybersecurity"
    PCI_DSS = "PCI_DSS"
    SOC_2 = "SOC_2"
    CUSTOM = "custom"


@dataclass
class ValidationResult:
    """Result of input validation."""
    is_valid: bool
    errors: list
    warnings: list


class InputValidator:
    """Validates all input parameters for the AWS Security Audit Tool."""
    
    # AWS Account ID pattern: 12 digits
    AWS_ACCOUNT_ID_PATTERN = re.compile(r'^\d{12}$')
    
    # ARN pattern for IAM roles
    IAM_ROLE_ARN_PATTERN = re.compile(
        r'^arn:aws:iam::\d{12}:role/[\w+=,.@-]+$'
    )
    
    def __init__(self):
        self.errors = []
        self.warnings = []
    
    def validate_aws_account_id(self, account_id: str) -> bool:
        """Validate AWS account ID format."""
        if not account_id:
            self.errors.append("AWS account ID is required")
            return False
        
        if not isinstance(account_id, str):
            self.errors.append("AWS account ID must be a string")
            return False
        
        if not self.AWS_ACCOUNT_ID_PATTERN.match(account_id):
            self.errors.append(
                "AWS account ID must be a 12-digit numeric string"
            )
            return False
        
        return True
    
    def validate_auth_method(self, auth_method: str, **kwargs) -> bool:
        """Validate authentication method and related parameters."""
        if not auth_method:
            self.errors.append("Authentication method is required")
            return False
        
        try:
            method = AuthMethod(auth_method.lower())
        except ValueError:
            self.errors.append(
                f"Invalid authentication method: {auth_method}. "
                f"Must be one of: {', '.join([m.value for m in AuthMethod])}"
            )
            return False
        
        # Validate method-specific parameters
        if method == AuthMethod.PROFILE:
            return self._validate_profile_auth(kwargs.get('profile_name'))
        elif method == AuthMethod.ROLE:
            return self._validate_role_auth(kwargs.get('role_arn'))
        elif method == AuthMethod.KEYS:
            return self._validate_keys_auth(
                kwargs.get('access_key_id'),
                kwargs.get('secret_access_key')
            )
        elif method == AuthMethod.INSTANCE:
            return self._validate_instance_auth()
        
        return True
    
    def _validate_profile_auth(self, profile_name: Optional[str]) -> bool:
        """Validate AWS CLI profile authentication."""
        if not profile_name:
            self.warnings.append("No profile name specified, will use default")
            return True
        
        if not isinstance(profile_name, str):
            self.errors.append("Profile name must be a string")
            return False
        
        if len(profile_name.strip()) == 0:
            self.errors.append("Profile name cannot be empty")
            return False
        
        return True
    
    def _validate_role_auth(self, role_arn: Optional[str]) -> bool:
        """Validate IAM role authentication."""
        if not role_arn:
            self.errors.append("Role ARN is required for role authentication")
            return False
        
        if not isinstance(role_arn, str):
            self.errors.append("Role ARN must be a string")
            return False
        
        if not self.IAM_ROLE_ARN_PATTERN.match(role_arn):
            self.errors.append(
                "Invalid role ARN format. Must be: "
                "arn:aws:iam::ACCOUNT-ID:role/ROLE-NAME"
            )
            return False
        
        return True
    
    def _validate_keys_auth(self, access_key_id: Optional[str], 
                           secret_access_key: Optional[str]) -> bool:
        """Validate access key authentication."""
        if not access_key_id:
            self.errors.append("Access key ID is required for key authentication")
            return False
        
        if not secret_access_key:
            self.errors.append("Secret access key is required for key authentication")
            return False
        
        # Basic format validation for access key ID
        if not isinstance(access_key_id, str) or len(access_key_id) != 20:
            self.errors.append("Access key ID must be a 20-character string")
            return False
        
        # Basic format validation for secret access key
        if not isinstance(secret_access_key, str) or len(secret_access_key) != 40:
            self.errors.append("Secret access key must be a 40-character string")
            return False
        
        self.warnings.append(
            "Using access keys directly is less secure than other methods"
        )
        return True
    
    def _validate_instance_auth(self) -> bool:
        """Validate EC2 instance profile authentication."""
        self.warnings.append(
            "Instance profile authentication requires tool to run on EC2 instance"
        )
        return True
    
    def validate_security_profile(self, profile_name: str, 
                                 config_file: Optional[str] = None) -> bool:
        """Validate security profile selection."""
        if not profile_name:
            self.errors.append("Security profile is required")
            return False
        
        try:
            profile = SecurityProfile(profile_name)
        except ValueError:
            self.errors.append(
                f"Invalid security profile: {profile_name}. "
                f"Must be one of: {', '.join([p.value for p in SecurityProfile])}"
            )
            return False
        
        # Custom profiles require config file
        if profile == SecurityProfile.CUSTOM:
            if not config_file:
                self.errors.append(
                    "Custom security profile requires --config-file parameter"
                )
                return False
            
            if not isinstance(config_file, str) or not config_file.strip():
                self.errors.append("Config file path cannot be empty")
                return False
        
        return True
    
    def validate_output_options(self, output_formats: list, 
                               output_dir: Optional[str] = None) -> bool:
        """Validate output format and directory options."""
        valid_formats = ['json', 'csv', 'markdown']
        
        if not output_formats:
            self.warnings.append("No output formats specified, using markdown")
            return True
        
        if not isinstance(output_formats, list):
            self.errors.append("Output formats must be a list")
            return False
        
        for fmt in output_formats:
            if fmt not in valid_formats:
                self.errors.append(
                    f"Invalid output format: {fmt}. "
                    f"Must be one of: {', '.join(valid_formats)}"
                )
                return False
        
        if output_dir:
            if not isinstance(output_dir, str) or not output_dir.strip():
                self.errors.append("Output directory path cannot be empty")
                return False
        
        return True
    
    def validate_execution_options(self, parallel_checks: Optional[int] = None,
                                  regions: Optional[list] = None) -> bool:
        """Validate execution options."""
        if parallel_checks is not None:
            if not isinstance(parallel_checks, int):
                self.errors.append("Parallel checks must be an integer")
                return False
            
            if parallel_checks < 1:
                self.errors.append("Parallel checks must be at least 1")
                return False
            
            if parallel_checks > 50:
                self.warnings.append(
                    "High parallel check count may cause API rate limiting"
                )
        
        if regions:
            if not isinstance(regions, list):
                self.errors.append("Regions must be a list")
                return False
            
            # Basic AWS region format validation
            region_pattern = re.compile(r'^[a-z]{2}-[a-z]+-\d{1}$')
            for region in regions:
                if not isinstance(region, str) or not region_pattern.match(region):
                    self.errors.append(f"Invalid AWS region format: {region}")
                    return False
        
        return True
    
    def validate_all(self, params: Dict[str, Any]) -> ValidationResult:
        """Validate all input parameters."""
        self.errors = []
        self.warnings = []
        
        # Validate required parameters
        self.validate_aws_account_id(params.get('account_id'))
        
        self.validate_auth_method(
            params.get('auth_method'),
            profile_name=params.get('profile_name'),
            role_arn=params.get('role_arn'),
            access_key_id=params.get('access_key_id'),
            secret_access_key=params.get('secret_access_key')
        )
        
        self.validate_security_profile(
            params.get('security_profile'),
            params.get('config_file')
        )
        
        # Validate optional parameters
        self.validate_output_options(
            params.get('output_formats', []),
            params.get('output_dir')
        )
        
        self.validate_execution_options(
            params.get('parallel_checks'),
            params.get('regions')
        )
        
        return ValidationResult(
            is_valid=len(self.errors) == 0,
            errors=self.errors.copy(),
            warnings=self.warnings.copy()
        )