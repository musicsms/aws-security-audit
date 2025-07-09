"""S3 security checks for AWS Security Audit Tool."""

import logging
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError

from ..aws_client import AWSClientManager
from ..config_manager import CheckConfig, Severity
from .base_checks import BaseSecurityChecks, CheckResult, CheckStatus


class S3SecurityChecks(BaseSecurityChecks):
    """S3 security checks implementation."""
    
    def __init__(self, aws_client: AWSClientManager):
        super().__init__(aws_client)
    
    def check_bucket_public_access(self, bucket_name: str, config: CheckConfig) -> CheckResult:
        """Check if S3 bucket has public access blocked."""
        try:
            s3_client = self.aws_client.get_client('s3')
            
            # Check public access block configuration
            try:
                response = s3_client.get_public_access_block(Bucket=bucket_name)
                pab_config = response['PublicAccessBlockConfiguration']
                
                block_public_acls = pab_config.get('BlockPublicAcls', False)
                ignore_public_acls = pab_config.get('IgnorePublicAcls', False)
                block_public_policy = pab_config.get('BlockPublicPolicy', False)
                restrict_public_buckets = pab_config.get('RestrictPublicBuckets', False)
                
                all_blocked = all([
                    block_public_acls,
                    ignore_public_acls,
                    block_public_policy,
                    restrict_public_buckets
                ])
                
                if all_blocked:
                    return CheckResult(
                        check_id="S3.1",
                        name="Bucket Public Access",
                        status=CheckStatus.OK,
                        severity=config.severity,
                        description="S3 bucket has public access blocked",
                        evidence=f"Public access block enabled: BlockPublicAcls={block_public_acls}, IgnorePublicAcls={ignore_public_acls}, BlockPublicPolicy={block_public_policy}, RestrictPublicBuckets={restrict_public_buckets}",
                        remediation=None,
                        resource_id=bucket_name
                    )
                else:
                    return CheckResult(
                        check_id="S3.1",
                        name="Bucket Public Access",
                        status=CheckStatus.NOK,
                        severity=config.severity,
                        description="S3 bucket does not have all public access blocked",
                        evidence=f"Public access block partial: BlockPublicAcls={block_public_acls}, IgnorePublicAcls={ignore_public_acls}, BlockPublicPolicy={block_public_policy}, RestrictPublicBuckets={restrict_public_buckets}",
                        remediation="Enable all public access block settings for the S3 bucket",
                        resource_id=bucket_name
                    )
            
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    return CheckResult(
                        check_id="S3.1",
                        name="Bucket Public Access",
                        status=CheckStatus.NOK,
                        severity=config.severity,
                        description="S3 bucket has no public access block configuration",
                        evidence="No public access block configuration found",
                        remediation="Configure public access block settings for the S3 bucket",
                        resource_id=bucket_name
                    )
                else:
                    raise
        
        except Exception as e:
            self.logger.error(f"Error checking bucket public access for {bucket_name}: {e}")
            return CheckResult(
                check_id="S3.1",
                name="Bucket Public Access",
                status=CheckStatus.ERROR,
                severity=config.severity,
                description="Error checking bucket public access",
                evidence=f"Error: {str(e)}",
                remediation="Check bucket permissions and retry",
                resource_id=bucket_name
            )
    
    def check_bucket_encryption(self, bucket_name: str, config: CheckConfig) -> CheckResult:
        """Check if S3 bucket has encryption enabled."""
        try:
            s3_client = self.aws_client.get_client('s3')
            
            try:
                response = s3_client.get_bucket_encryption(Bucket=bucket_name)
                encryption_config = response['ServerSideEncryptionConfiguration']
                
                rules = encryption_config.get('Rules', [])
                if not rules:
                    return CheckResult(
                        check_id="S3.2",
                        name="Bucket Encryption",
                        status=CheckStatus.NOK,
                        severity=config.severity,
                        description="S3 bucket has no encryption rules",
                        evidence="No server-side encryption rules found",
                        remediation="Configure server-side encryption for the S3 bucket",
                        resource_id=bucket_name
                    )
                
                # Check encryption algorithm
                rule = rules[0]
                sse_algorithm = rule.get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm', '')
                
                require_kms = config.parameters.get('require_kms', False)
                allow_s3_managed = config.parameters.get('allow_s3_managed', True)
                
                if sse_algorithm == 'aws:kms':
                    kms_key_id = rule.get('ApplyServerSideEncryptionByDefault', {}).get('KMSMasterKeyID', '')
                    return CheckResult(
                        check_id="S3.2",
                        name="Bucket Encryption",
                        status=CheckStatus.OK,
                        severity=config.severity,
                        description="S3 bucket has KMS encryption enabled",
                        evidence=f"KMS encryption enabled with key: {kms_key_id or 'default'}",
                        remediation=None,
                        resource_id=bucket_name
                    )
                elif sse_algorithm == 'AES256':
                    if allow_s3_managed:
                        status = CheckStatus.OK if not require_kms else CheckStatus.NEED_REVIEW
                        return CheckResult(
                            check_id="S3.2",
                            name="Bucket Encryption",
                            status=status,
                            severity=config.severity,
                            description="S3 bucket has AES256 encryption enabled",
                            evidence="AES256 (S3-managed) encryption enabled",
                            remediation="Consider upgrading to KMS encryption for better key management" if require_kms else None,
                            resource_id=bucket_name
                        )
                    else:
                        return CheckResult(
                            check_id="S3.2",
                            name="Bucket Encryption",
                            status=CheckStatus.NOK,
                            severity=config.severity,
                            description="S3 bucket uses S3-managed encryption but KMS is required",
                            evidence="AES256 (S3-managed) encryption enabled but KMS required",
                            remediation="Configure KMS encryption for the S3 bucket",
                            resource_id=bucket_name
                        )
                else:
                    return CheckResult(
                        check_id="S3.2",
                        name="Bucket Encryption",
                        status=CheckStatus.NOK,
                        severity=config.severity,
                        description="S3 bucket has unknown encryption algorithm",
                        evidence=f"Unknown encryption algorithm: {sse_algorithm}",
                        remediation="Configure standard encryption (AES256 or KMS) for the S3 bucket",
                        resource_id=bucket_name
                    )
            
            except ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    return CheckResult(
                        check_id="S3.2",
                        name="Bucket Encryption",
                        status=CheckStatus.NOK,
                        severity=config.severity,
                        description="S3 bucket has no encryption configuration",
                        evidence="No server-side encryption configuration found",
                        remediation="Configure server-side encryption for the S3 bucket",
                        resource_id=bucket_name
                    )
                else:
                    raise
        
        except Exception as e:
            self.logger.error(f"Error checking bucket encryption for {bucket_name}: {e}")
            return CheckResult(
                check_id="S3.2",
                name="Bucket Encryption",
                status=CheckStatus.ERROR,
                severity=config.severity,
                description="Error checking bucket encryption",
                evidence=f"Error: {str(e)}",
                remediation="Check bucket permissions and retry",
                resource_id=bucket_name
            )
    
    def check_bucket_logging(self, bucket_name: str, config: CheckConfig) -> CheckResult:
        """Check if S3 bucket has access logging enabled."""
        try:
            s3_client = self.aws_client.get_client('s3')
            
            try:
                response = s3_client.get_bucket_logging(Bucket=bucket_name)
                logging_config = response.get('LoggingEnabled', {})
                
                if not logging_config:
                    return CheckResult(
                        check_id="S3.3",
                        name="Bucket Logging",
                        status=CheckStatus.NOK,
                        severity=config.severity,
                        description="S3 bucket has no access logging configured",
                        evidence="No logging configuration found",
                        remediation="Configure access logging for the S3 bucket",
                        resource_id=bucket_name
                    )
                
                target_bucket = logging_config.get('TargetBucket', '')
                target_prefix = logging_config.get('TargetPrefix', '')
                
                if target_bucket:
                    return CheckResult(
                        check_id="S3.3",
                        name="Bucket Logging",
                        status=CheckStatus.OK,
                        severity=config.severity,
                        description="S3 bucket has access logging enabled",
                        evidence=f"Access logs sent to bucket: {target_bucket} with prefix: {target_prefix}",
                        remediation=None,
                        resource_id=bucket_name
                    )
                else:
                    return CheckResult(
                        check_id="S3.3",
                        name="Bucket Logging",
                        status=CheckStatus.NEED_REVIEW,
                        severity=config.severity,
                        description="S3 bucket logging configuration incomplete",
                        evidence="Logging configured but no target bucket specified",
                        remediation="Complete the logging configuration with target bucket",
                        resource_id=bucket_name
                    )
            
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucket':
                    return CheckResult(
                        check_id="S3.3",
                        name="Bucket Logging",
                        status=CheckStatus.ERROR,
                        severity=config.severity,
                        description="S3 bucket not found",
                        evidence="Bucket does not exist",
                        remediation="Verify bucket name and permissions",
                        resource_id=bucket_name
                    )
                else:
                    raise
        
        except Exception as e:
            self.logger.error(f"Error checking bucket logging for {bucket_name}: {e}")
            return CheckResult(
                check_id="S3.3",
                name="Bucket Logging",
                status=CheckStatus.ERROR,
                severity=config.severity,
                description="Error checking bucket logging",
                evidence=f"Error: {str(e)}",
                remediation="Check bucket permissions and retry",
                resource_id=bucket_name
            )
    
    def check_bucket_versioning(self, bucket_name: str, config: CheckConfig) -> CheckResult:
        """Check if S3 bucket has versioning enabled."""
        try:
            s3_client = self.aws_client.get_client('s3')
            
            response = s3_client.get_bucket_versioning(Bucket=bucket_name)
            versioning_status = response.get('Status', 'Disabled')
            mfa_delete = response.get('MFADelete', 'Disabled')
            
            require_versioning = config.parameters.get('require_versioning', True)
            check_mfa_delete = config.parameters.get('check_mfa_delete', False)
            
            if versioning_status == 'Enabled':
                if check_mfa_delete and mfa_delete != 'Enabled':
                    return CheckResult(
                        check_id="S3.4",
                        name="Bucket Versioning",
                        status=CheckStatus.NEED_REVIEW,
                        severity=config.severity,
                        description="S3 bucket versioning enabled but MFA delete not configured",
                        evidence=f"Versioning: {versioning_status}, MFA Delete: {mfa_delete}",
                        remediation="Consider enabling MFA delete for additional protection",
                        resource_id=bucket_name
                    )
                else:
                    return CheckResult(
                        check_id="S3.4",
                        name="Bucket Versioning",
                        status=CheckStatus.OK,
                        severity=config.severity,
                        description="S3 bucket has versioning enabled",
                        evidence=f"Versioning: {versioning_status}, MFA Delete: {mfa_delete}",
                        remediation=None,
                        resource_id=bucket_name
                    )
            elif versioning_status == 'Suspended':
                return CheckResult(
                    check_id="S3.4",
                    name="Bucket Versioning",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="S3 bucket versioning is suspended",
                    evidence=f"Versioning: {versioning_status}",
                    remediation="Re-enable versioning for the S3 bucket",
                    resource_id=bucket_name
                )
            else:
                status = CheckStatus.NOK if require_versioning else CheckStatus.NEED_REVIEW
                return CheckResult(
                    check_id="S3.4",
                    name="Bucket Versioning",
                    status=status,
                    severity=config.severity,
                    description="S3 bucket has versioning disabled",
                    evidence=f"Versioning: {versioning_status}",
                    remediation="Enable versioning for the S3 bucket",
                    resource_id=bucket_name
                )
        
        except Exception as e:
            self.logger.error(f"Error checking bucket versioning for {bucket_name}: {e}")
            return CheckResult(
                check_id="S3.4",
                name="Bucket Versioning",
                status=CheckStatus.ERROR,
                severity=config.severity,
                description="Error checking bucket versioning",
                evidence=f"Error: {str(e)}",
                remediation="Check bucket permissions and retry",
                resource_id=bucket_name
            )
    
    def run_all_checks(self, bucket_names: List[str], config_checks: Dict[str, CheckConfig], region: str = None) -> List[CheckResult]:
        """Run all S3 security checks for given buckets.
        
        Args:
            bucket_names: List of S3 bucket names to check
            config_checks: Dictionary of check configurations
            region: AWS region being checked
            
        Returns:
            List of CheckResult objects
        """
        results = []
        
        for bucket_name in bucket_names:
            self.logger.info(f"Running S3 security checks for bucket: {bucket_name}")
            
            # Public access check
            if 'public_access' in config_checks:
                result = self.check_bucket_public_access(bucket_name, config_checks['public_access'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
            
            # Encryption check
            if 'encryption' in config_checks:
                result = self.check_bucket_encryption(bucket_name, config_checks['encryption'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
            
            # Logging check
            if 'logging' in config_checks:
                result = self.check_bucket_logging(bucket_name, config_checks['logging'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
            
            # Versioning check
            if 'versioning' in config_checks:
                result = self.check_bucket_versioning(bucket_name, config_checks['versioning'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
        
        return results