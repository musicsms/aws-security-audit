"""Configuration Manager for AWS Security Audit Tool."""

import yaml
import json
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum


class Severity(Enum):
    """Security check severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CheckConfig:
    """Configuration for individual security check."""
    enabled: bool = True
    severity: Severity = Severity.MEDIUM
    parameters: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    remediation: str = ""


@dataclass
class CategoryConfig:
    """Configuration for service category checks."""
    enabled: bool = True
    checks: Dict[str, CheckConfig] = field(default_factory=dict)
    description: str = ""


@dataclass
class SecurityProfile:
    """Complete security profile configuration."""
    name: str
    description: str
    version: str
    categories: Dict[str, CategoryConfig] = field(default_factory=dict)


class ConfigManager:
    """Manages security profile configurations and check parameters."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.profiles = {}
        self._load_builtin_profiles()
    
    def _load_builtin_profiles(self) -> None:
        """Load built-in security profiles."""
        self.profiles = {
            'CIS_AWS_Foundations': self._create_cis_profile(),
            'NIST_Cybersecurity': self._create_nist_profile(),
            'PCI_DSS': self._create_pci_profile(),
            'SOC_2': self._create_soc2_profile()
        }
    
    def _create_cis_profile(self) -> SecurityProfile:
        """Create CIS AWS Foundations Benchmark profile."""
        return SecurityProfile(
            name="CIS AWS Foundations Benchmark",
            description="Center for Internet Security AWS Foundations Benchmark v1.4.0",
            version="1.4.0",
            categories={
                "s3": CategoryConfig(
                    enabled=True,
                    description="S3 bucket security checks",
                    checks={
                        "public_access": CheckConfig(
                            enabled=True,
                            severity=Severity.CRITICAL,
                            parameters={
                                "allow_public_read": False,
                                "allow_public_write": False,
                                "check_bucket_policy": True
                            },
                            description="Ensure S3 buckets are not publicly accessible",
                            remediation="Configure S3 bucket public access block settings"
                        ),
                        "encryption": CheckConfig(
                            enabled=True,
                            severity=Severity.HIGH,
                            parameters={
                                "require_kms": True,
                                "allow_s3_managed": False
                            },
                            description="Ensure S3 bucket encryption is enabled",
                            remediation="Enable S3 bucket encryption with KMS keys"
                        ),
                        "logging": CheckConfig(
                            enabled=True,
                            severity=Severity.MEDIUM,
                            parameters={
                                "require_access_logging": True,
                                "check_log_delivery": True
                            },
                            description="Ensure S3 bucket access logging is enabled",
                            remediation="Enable S3 bucket access logging"
                        ),
                        "versioning": CheckConfig(
                            enabled=True,
                            severity=Severity.MEDIUM,
                            parameters={
                                "require_versioning": True,
                                "check_mfa_delete": True
                            },
                            description="Ensure S3 bucket versioning is enabled",
                            remediation="Enable S3 bucket versioning and MFA delete"
                        )
                    }
                ),
                "ec2": CategoryConfig(
                    enabled=True,
                    description="EC2 instance security checks",
                    checks={
                        "security_groups": CheckConfig(
                            enabled=True,
                            severity=Severity.HIGH,
                            parameters={
                                "allow_unrestricted_ssh": False,
                                "allow_unrestricted_rdp": False,
                                "check_ingress_rules": True
                            },
                            description="Ensure EC2 security groups restrict access",
                            remediation="Review and restrict EC2 security group rules"
                        ),
                        "ebs_encryption": CheckConfig(
                            enabled=True,
                            severity=Severity.HIGH,
                            parameters={
                                "require_encryption": True,
                                "check_default_encryption": True
                            },
                            description="Ensure EBS volumes are encrypted",
                            remediation="Enable EBS volume encryption"
                        ),
                        "imds_v2": CheckConfig(
                            enabled=True,
                            severity=Severity.MEDIUM,
                            parameters={
                                "require_imds_v2": True,
                                "check_token_required": True
                            },
                            description="Ensure EC2 instances use IMDSv2",
                            remediation="Configure EC2 instances to require IMDSv2"
                        )
                    }
                ),
                "rds": CategoryConfig(
                    enabled=True,
                    description="RDS database security checks",
                    checks={
                        "encryption": CheckConfig(
                            enabled=True,
                            severity=Severity.HIGH,
                            parameters={
                                "require_encryption_at_rest": True,
                                "require_encryption_in_transit": True
                            },
                            description="Ensure RDS encryption is enabled",
                            remediation="Enable RDS encryption at rest and in transit"
                        ),
                        "public_access": CheckConfig(
                            enabled=True,
                            severity=Severity.CRITICAL,
                            parameters={
                                "allow_public_access": False,
                                "check_subnet_groups": True
                            },
                            description="Ensure RDS instances are not publicly accessible",
                            remediation="Configure RDS instances in private subnets"
                        ),
                        "backup": CheckConfig(
                            enabled=True,
                            severity=Severity.MEDIUM,
                            parameters={
                                "minimum_backup_retention": 7,
                                "require_automated_backups": True
                            },
                            description="Ensure RDS automated backups are enabled",
                            remediation="Enable RDS automated backups with adequate retention"
                        )
                    }
                ),
                "vpc": CategoryConfig(
                    enabled=True,
                    description="VPC network security checks",
                    checks={
                        "flow_logs": CheckConfig(
                            enabled=True,
                            severity=Severity.MEDIUM,
                            parameters={
                                "require_flow_logs": True,
                                "check_all_vpcs": True
                            },
                            description="Ensure VPC flow logs are enabled",
                            remediation="Enable VPC flow logs for all VPCs"
                        ),
                        "default_vpc": CheckConfig(
                            enabled=True,
                            severity=Severity.LOW,
                            parameters={
                                "flag_default_vpc_usage": True,
                                "recommend_deletion": True
                            },
                            description="Ensure default VPC is not used",
                            remediation="Create custom VPC and delete default VPC"
                        )
                    }
                ),
                "kms": CategoryConfig(
                    enabled=True,
                    description="KMS key management checks",
                    checks={
                        "key_rotation": CheckConfig(
                            enabled=True,
                            severity=Severity.MEDIUM,
                            parameters={
                                "require_rotation": True,
                                "rotation_interval_days": 365
                            },
                            description="Ensure KMS key rotation is enabled",
                            remediation="Enable automatic key rotation for KMS keys"
                        ),
                        "key_policy": CheckConfig(
                            enabled=True,
                            severity=Severity.HIGH,
                            parameters={
                                "check_overly_permissive": True,
                                "flag_star_principals": True
                            },
                            description="Ensure KMS key policies are secure",
                            remediation="Review and restrict KMS key policies"
                        )
                    }
                )
            }
        )
    
    def _create_nist_profile(self) -> SecurityProfile:
        """Create NIST Cybersecurity Framework profile."""
        return SecurityProfile(
            name="NIST Cybersecurity Framework",
            description="NIST Cybersecurity Framework mapping for AWS",
            version="1.1",
            categories={
                "s3": CategoryConfig(
                    enabled=True,
                    checks={
                        "public_access": CheckConfig(
                            enabled=True,
                            severity=Severity.HIGH,
                            parameters={
                                "allow_public_read": False,
                                "allow_public_write": False
                            }
                        ),
                        "encryption": CheckConfig(
                            enabled=True,
                            severity=Severity.HIGH,
                            parameters={
                                "require_kms": True,
                                "allow_s3_managed": True
                            }
                        )
                    }
                ),
                "ec2": CategoryConfig(
                    enabled=True,
                    checks={
                        "security_groups": CheckConfig(
                            enabled=True,
                            severity=Severity.HIGH,
                            parameters={
                                "allow_unrestricted_ssh": False,
                                "allow_unrestricted_rdp": False
                            }
                        ),
                        "ebs_encryption": CheckConfig(
                            enabled=True,
                            severity=Severity.MEDIUM,
                            parameters={
                                "require_encryption": True
                            }
                        )
                    }
                )
            }
        )
    
    def _create_pci_profile(self) -> SecurityProfile:
        """Create PCI DSS compliance profile."""
        return SecurityProfile(
            name="PCI DSS Compliance",
            description="Payment Card Industry Data Security Standard compliance",
            version="4.0",
            categories={
                "s3": CategoryConfig(
                    enabled=True,
                    checks={
                        "public_access": CheckConfig(
                            enabled=True,
                            severity=Severity.CRITICAL,
                            parameters={
                                "allow_public_read": False,
                                "allow_public_write": False
                            }
                        ),
                        "encryption": CheckConfig(
                            enabled=True,
                            severity=Severity.CRITICAL,
                            parameters={
                                "require_kms": True,
                                "allow_s3_managed": False
                            }
                        )
                    }
                ),
                "rds": CategoryConfig(
                    enabled=True,
                    checks={
                        "encryption": CheckConfig(
                            enabled=True,
                            severity=Severity.CRITICAL,
                            parameters={
                                "require_encryption_at_rest": True,
                                "require_encryption_in_transit": True
                            }
                        )
                    }
                )
            }
        )
    
    def _create_soc2_profile(self) -> SecurityProfile:
        """Create SOC 2 compliance profile."""
        return SecurityProfile(
            name="SOC 2 Compliance",
            description="Service Organization Control 2 compliance",
            version="2017",
            categories={
                "s3": CategoryConfig(
                    enabled=True,
                    checks={
                        "public_access": CheckConfig(
                            enabled=True,
                            severity=Severity.HIGH,
                            parameters={
                                "allow_public_read": False,
                                "allow_public_write": False
                            }
                        ),
                        "logging": CheckConfig(
                            enabled=True,
                            severity=Severity.HIGH,
                            parameters={
                                "require_access_logging": True
                            }
                        )
                    }
                ),
                "vpc": CategoryConfig(
                    enabled=True,
                    checks={
                        "flow_logs": CheckConfig(
                            enabled=True,
                            severity=Severity.HIGH,
                            parameters={
                                "require_flow_logs": True
                            }
                        )
                    }
                )
            }
        )
    
    def load_custom_profile(self, config_file: str) -> SecurityProfile:
        """Load custom security profile from file.
        
        Args:
            config_file: Path to YAML configuration file
            
        Returns:
            SecurityProfile instance
        """
        config_path = Path(config_file)
        
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_file}")
        
        try:
            with open(config_path, 'r') as f:
                if config_path.suffix.lower() == '.json':
                    config_data = json.load(f)
                else:
                    config_data = yaml.safe_load(f)
            
            return self._parse_config_data(config_data)
            
        except Exception as e:
            self.logger.error(f"Failed to load configuration file: {e}")
            raise
    
    def _parse_config_data(self, config_data: Dict[str, Any]) -> SecurityProfile:
        """Parse configuration data into SecurityProfile."""
        profile = SecurityProfile(
            name=config_data.get('name', 'Custom Profile'),
            description=config_data.get('description', ''),
            version=config_data.get('version', '1.0')
        )
        
        categories_data = config_data.get('categories', {})
        
        for category_name, category_data in categories_data.items():
            category = CategoryConfig(
                enabled=category_data.get('enabled', True),
                description=category_data.get('description', '')
            )
            
            checks_data = category_data.get('checks', {})
            for check_name, check_data in checks_data.items():
                check = CheckConfig(
                    enabled=check_data.get('enabled', True),
                    severity=Severity(check_data.get('severity', 'medium')),
                    parameters=check_data.get('parameters', {}),
                    description=check_data.get('description', ''),
                    remediation=check_data.get('remediation', '')
                )
                category.checks[check_name] = check
            
            profile.categories[category_name] = category
        
        return profile
    
    def get_profile(self, profile_name: str, config_file: Optional[str] = None) -> SecurityProfile:
        """Get security profile by name.
        
        Args:
            profile_name: Name of the security profile
            config_file: Optional custom configuration file for custom profiles
            
        Returns:
            SecurityProfile instance
        """
        if profile_name == 'custom':
            if not config_file:
                raise ValueError("Custom profile requires config_file parameter")
            return self.load_custom_profile(config_file)
        
        if profile_name not in self.profiles:
            raise ValueError(f"Unknown security profile: {profile_name}")
        
        return self.profiles[profile_name]
    
    def list_profiles(self) -> List[str]:
        """List available built-in security profiles."""
        return list(self.profiles.keys())
    
    def get_check_config(self, profile: SecurityProfile, category: str, check: str) -> Optional[CheckConfig]:
        """Get specific check configuration.
        
        Args:
            profile: Security profile
            category: Service category (e.g., 's3', 'ec2')
            check: Check name
            
        Returns:
            CheckConfig instance or None if not found
        """
        if category not in profile.categories:
            return None
        
        category_config = profile.categories[category]
        if not category_config.enabled:
            return None
        
        if check not in category_config.checks:
            return None
        
        check_config = category_config.checks[check]
        return check_config if check_config.enabled else None
    
    def export_profile(self, profile: SecurityProfile, output_file: str) -> None:
        """Export security profile to YAML file.
        
        Args:
            profile: Security profile to export
            output_file: Output file path
        """
        config_data = {
            'name': profile.name,
            'description': profile.description,
            'version': profile.version,
            'categories': {}
        }
        
        for category_name, category in profile.categories.items():
            category_data = {
                'enabled': category.enabled,
                'description': category.description,
                'checks': {}
            }
            
            for check_name, check in category.checks.items():
                check_data = {
                    'enabled': check.enabled,
                    'severity': check.severity.value,
                    'parameters': check.parameters,
                    'description': check.description,
                    'remediation': check.remediation
                }
                category_data['checks'][check_name] = check_data
            
            config_data['categories'][category_name] = category_data
        
        with open(output_file, 'w') as f:
            yaml.safe_dump(config_data, f, default_flow_style=False, indent=2)
        
        self.logger.info(f"Security profile exported to {output_file}")
    
    def validate_profile(self, profile: SecurityProfile) -> List[str]:
        """Validate security profile configuration.
        
        Args:
            profile: Security profile to validate
            
        Returns:
            List of validation errors
        """
        errors = []
        
        if not profile.name:
            errors.append("Profile name is required")
        
        if not profile.categories:
            errors.append("Profile must have at least one category")
        
        for category_name, category in profile.categories.items():
            if not category.checks:
                errors.append(f"Category '{category_name}' has no checks defined")
            
            for check_name, check in category.checks.items():
                if not check.description:
                    errors.append(f"Check '{category_name}.{check_name}' missing description")
        
        return errors