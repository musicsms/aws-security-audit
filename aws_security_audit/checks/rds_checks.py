"""RDS security checks for AWS Security Audit Tool."""

import logging
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError

from ..aws_client import AWSClientManager
from ..config_manager import CheckConfig, Severity
from .base_checks import BaseSecurityChecks, CheckResult, CheckStatus


class RDSSecurityChecks(BaseSecurityChecks):
    """RDS security checks implementation."""
    
    def __init__(self, aws_client: AWSClientManager):
        super().__init__(aws_client)
    
    def check_instance_encryption(self, instance: Dict[str, Any], config: CheckConfig) -> CheckResult:
        """Check if RDS instance has encryption enabled."""
        try:
            instance_id = instance.get('DBInstanceIdentifier', '')
            encrypted = instance.get('StorageEncrypted', False)
            kms_key_id = instance.get('KmsKeyId', '')
            
            require_encryption = config.parameters.get('require_encryption_at_rest', True)
            
            if encrypted:
                return CheckResult(
                    check_id="RDS.1",
                    name="RDS Instance Encryption",
                    status=CheckStatus.OK,
                    severity=config.severity,
                    description="RDS instance has encryption enabled",
                    evidence=f"Storage encrypted with KMS key: {kms_key_id or 'default'}",
                    remediation=None,
                    resource_id=instance_id
                )
            else:
                status = CheckStatus.NOK if require_encryption else CheckStatus.NEED_REVIEW
                return CheckResult(
                    check_id="RDS.1",
                    name="RDS Instance Encryption",
                    status=status,
                    severity=config.severity,
                    description="RDS instance does not have encryption enabled",
                    evidence="Storage encryption is disabled",
                    remediation="Enable encryption by creating encrypted read replica and promoting it",
                    resource_id=instance_id
                )
        
        except Exception as e:
            return self.create_error_result("RDS.1", "RDS Instance Encryption", 
                                          config.severity, instance_id, e)
    
    def check_instance_public_access(self, instance: Dict[str, Any], config: CheckConfig) -> CheckResult:
        """Check if RDS instance is publicly accessible."""
        try:
            instance_id = instance.get('DBInstanceIdentifier', '')
            publicly_accessible = instance.get('PubliclyAccessible', False)
            
            allow_public_access = config.parameters.get('allow_public_access', False)
            
            if publicly_accessible:
                status = CheckStatus.NOK if not allow_public_access else CheckStatus.NEED_REVIEW
                return CheckResult(
                    check_id="RDS.2",
                    name="RDS Instance Public Access",
                    status=status,
                    severity=Severity.CRITICAL,
                    description="RDS instance is publicly accessible",
                    evidence="PubliclyAccessible=True",
                    remediation="Modify instance to disable public accessibility",
                    resource_id=instance_id
                )
            else:
                return CheckResult(
                    check_id="RDS.2",
                    name="RDS Instance Public Access",
                    status=CheckStatus.OK,
                    severity=config.severity,
                    description="RDS instance is not publicly accessible",
                    evidence="PubliclyAccessible=False",
                    remediation=None,
                    resource_id=instance_id
                )
        
        except Exception as e:
            return self.create_error_result("RDS.2", "RDS Instance Public Access", 
                                          config.severity, instance_id, e)
    
    def check_instance_backups(self, instance: Dict[str, Any], config: CheckConfig) -> CheckResult:
        """Check if RDS instance has automated backups enabled."""
        try:
            instance_id = instance.get('DBInstanceIdentifier', '')
            backup_retention_period = instance.get('BackupRetentionPeriod', 0)
            preferred_backup_window = instance.get('PreferredBackupWindow', '')
            
            minimum_retention = config.parameters.get('minimum_backup_retention', 7)
            require_automated_backups = config.parameters.get('require_automated_backups', True)
            
            if backup_retention_period > 0:
                if backup_retention_period >= minimum_retention:
                    return CheckResult(
                        check_id="RDS.3",
                        name="RDS Instance Backups",
                        status=CheckStatus.OK,
                        severity=config.severity,
                        description="RDS instance has adequate backup retention",
                        evidence=f"Backup retention: {backup_retention_period} days, Window: {preferred_backup_window}",
                        remediation=None,
                        resource_id=instance_id
                    )
                else:
                    return CheckResult(
                        check_id="RDS.3",
                        name="RDS Instance Backups",
                        status=CheckStatus.NEED_REVIEW,
                        severity=config.severity,
                        description="RDS instance has insufficient backup retention",
                        evidence=f"Backup retention: {backup_retention_period} days (minimum: {minimum_retention})",
                        remediation=f"Increase backup retention period to at least {minimum_retention} days",
                        resource_id=instance_id
                    )
            else:
                status = CheckStatus.NOK if require_automated_backups else CheckStatus.NEED_REVIEW
                return CheckResult(
                    check_id="RDS.3",
                    name="RDS Instance Backups",
                    status=status,
                    severity=config.severity,
                    description="RDS instance has automated backups disabled",
                    evidence="BackupRetentionPeriod=0",
                    remediation="Enable automated backups with appropriate retention period",
                    resource_id=instance_id
                )
        
        except Exception as e:
            return self.create_error_result("RDS.3", "RDS Instance Backups", 
                                          config.severity, instance_id, e)
    
    def check_instance_multi_az(self, instance: Dict[str, Any], config: CheckConfig) -> CheckResult:
        """Check if RDS instance has Multi-AZ deployment enabled."""
        try:
            instance_id = instance.get('DBInstanceIdentifier', '')
            multi_az = instance.get('MultiAZ', False)
            
            if multi_az:
                return CheckResult(
                    check_id="RDS.4",
                    name="RDS Instance Multi-AZ",
                    status=CheckStatus.OK,
                    severity=config.severity,
                    description="RDS instance has Multi-AZ deployment enabled",
                    evidence="MultiAZ=True",
                    remediation=None,
                    resource_id=instance_id
                )
            else:
                return CheckResult(
                    check_id="RDS.4",
                    name="RDS Instance Multi-AZ",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="RDS instance does not have Multi-AZ deployment",
                    evidence="MultiAZ=False",
                    remediation="Consider enabling Multi-AZ deployment for high availability",
                    resource_id=instance_id
                )
        
        except Exception as e:
            return self.create_error_result("RDS.4", "RDS Instance Multi-AZ", 
                                          config.severity, instance_id, e)
    
    def check_instance_deletion_protection(self, instance: Dict[str, Any], config: CheckConfig) -> CheckResult:
        """Check if RDS instance has deletion protection enabled."""
        try:
            instance_id = instance.get('DBInstanceIdentifier', '')
            deletion_protection = instance.get('DeletionProtection', False)
            
            if deletion_protection:
                return CheckResult(
                    check_id="RDS.5",
                    name="RDS Instance Deletion Protection",
                    status=CheckStatus.OK,
                    severity=config.severity,
                    description="RDS instance has deletion protection enabled",
                    evidence="DeletionProtection=True",
                    remediation=None,
                    resource_id=instance_id
                )
            else:
                return CheckResult(
                    check_id="RDS.5",
                    name="RDS Instance Deletion Protection",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="RDS instance does not have deletion protection enabled",
                    evidence="DeletionProtection=False",
                    remediation="Enable deletion protection for critical databases",
                    resource_id=instance_id
                )
        
        except Exception as e:
            return self.create_error_result("RDS.5", "RDS Instance Deletion Protection", 
                                          config.severity, instance_id, e)
    
    def run_all_checks(self, instances: List[Dict[str, Any]], config_checks: Dict[str, CheckConfig]) -> List[CheckResult]:
        """Run all RDS security checks for given instances.
        
        Args:
            instances: List of RDS instance dictionaries
            config_checks: Dictionary of check configurations
            
        Returns:
            List of CheckResult objects
        """
        results = []
        
        for instance in instances:
            instance_id = instance.get('DBInstanceIdentifier', 'unknown')
            self.logger.info(f"Running RDS security checks for instance: {instance_id}")
            
            # Encryption check
            if 'encryption' in config_checks:
                result = self.check_instance_encryption(instance, config_checks['encryption'])
                results.append(result)
            
            # Public access check
            if 'public_access' in config_checks:
                result = self.check_instance_public_access(instance, config_checks['public_access'])
                results.append(result)
            
            # Backup check
            if 'backup' in config_checks:
                result = self.check_instance_backups(instance, config_checks['backup'])
                results.append(result)
            
            # Multi-AZ check
            if 'multi_az' in config_checks:
                result = self.check_instance_multi_az(instance, config_checks['multi_az'])
                results.append(result)
            
            # Deletion protection check
            if 'deletion_protection' in config_checks:
                result = self.check_instance_deletion_protection(instance, config_checks['deletion_protection'])
                results.append(result)
        
        return results