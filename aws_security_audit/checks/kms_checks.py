"""KMS security checks for AWS Security Audit Tool."""

import logging
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError

from ..aws_client import AWSClientManager
from ..config_manager import CheckConfig, Severity
from .base_checks import BaseSecurityChecks, CheckResult, CheckStatus


class KMSSecurityChecks(BaseSecurityChecks):
    """KMS security checks implementation."""
    
    def __init__(self, aws_client: AWSClientManager):
        super().__init__(aws_client)
    
    def check_key_rotation(self, key: Dict[str, Any], config: CheckConfig) -> CheckResult:
        """Check if KMS key has rotation enabled."""
        try:
            key_id = key.get('KeyId', '')
            kms_client = self.aws_client.get_client('kms')
            
            # Only check customer-managed keys
            key_spec = key.get('KeySpec', '')
            key_usage = key.get('KeyUsage', '')
            origin = key.get('Origin', '')
            
            if origin != 'AWS_KMS':
                return CheckResult(
                    check_id="KMS.1",
                    name="KMS Key Rotation",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="KMS key has external key material",
                    evidence=f"Key origin: {origin}",
                    remediation="External key material cannot have automatic rotation",
                    resource_id=key_id
                )
            
            if key_usage != 'ENCRYPT_DECRYPT':
                return CheckResult(
                    check_id="KMS.1",
                    name="KMS Key Rotation",
                    status=CheckStatus.OK,
                    severity=config.severity,
                    description="KMS key is not used for encryption/decryption",
                    evidence=f"Key usage: {key_usage}",
                    remediation=None,
                    resource_id=key_id
                )
            
            # Check rotation status
            try:
                rotation_response = kms_client.get_key_rotation_status(KeyId=key_id)
                rotation_enabled = rotation_response.get('KeyRotationEnabled', False)
                
                require_rotation = config.parameters.get('require_rotation', True)
                
                # Create raw evidence
                raw_evidence = {
                    'key_metadata': key,
                    'rotation_response': rotation_response,
                    'api_call': 'get_key_rotation_status',
                    'parameters': {'KeyId': key_id}
                }
                
                if rotation_enabled:
                    return CheckResult(
                        check_id="KMS.1",
                        name="KMS Key Rotation",
                        status=CheckStatus.OK,
                        severity=config.severity,
                        description="KMS key has automatic rotation enabled",
                        evidence="KeyRotationEnabled=True",
                        remediation=None,
                        resource_id=key_id,
                        raw_evidence=raw_evidence
                    )
                else:
                    status = CheckStatus.NOK if require_rotation else CheckStatus.NEED_REVIEW
                    return CheckResult(
                        check_id="KMS.1",
                        name="KMS Key Rotation",
                        status=status,
                        severity=config.severity,
                        description="KMS key does not have automatic rotation enabled",
                        evidence="KeyRotationEnabled=False",
                        remediation="Enable automatic key rotation for better security",
                        resource_id=key_id,
                        raw_evidence=raw_evidence
                    )
            
            except ClientError as e:
                if e.response['Error']['Code'] == 'UnsupportedOperationException':
                    return CheckResult(
                        check_id="KMS.1",
                        name="KMS Key Rotation",
                        status=CheckStatus.OK,
                        severity=config.severity,
                        description="KMS key type does not support rotation",
                        evidence=f"Key spec: {key_spec}, Key usage: {key_usage}",
                        remediation=None,
                        resource_id=key_id
                    )
                else:
                    raise
        
        except Exception as e:
            return self.create_error_result("KMS.1", "KMS Key Rotation", 
                                          config.severity, key_id, e, 
                                          region=self.current_region)
    
    def check_key_policy(self, key: Dict[str, Any], config: CheckConfig) -> CheckResult:
        """Check KMS key policy for overly permissive access."""
        try:
            key_id = key.get('KeyId', '')
            kms_client = self.aws_client.get_client('kms')
            
            # Get key policy
            try:
                policy_response = kms_client.get_key_policy(
                    KeyId=key_id,
                    PolicyName='default'
                )
                
                policy_document = policy_response.get('Policy', '{}')
                
                # Basic policy analysis
                import json
                try:
                    policy = json.loads(policy_document)
                    statements = policy.get('Statement', [])
                    
                    issues = []
                    
                    for statement in statements:
                        principals = statement.get('Principal', {})
                        actions = statement.get('Action', [])
                        effect = statement.get('Effect', 'Deny')
                        
                        if effect == 'Allow':
                            # Check for overly broad principals
                            if isinstance(principals, str) and principals == '*':
                                issues.append("Policy allows access from any principal (*)")
                            elif isinstance(principals, dict):
                                aws_principals = principals.get('AWS', [])
                                if isinstance(aws_principals, str):
                                    aws_principals = [aws_principals]
                                
                                for principal in aws_principals:
                                    if principal == '*':
                                        issues.append("Policy allows access from any AWS principal")
                                    elif ':root' in principal:
                                        issues.append(f"Policy allows root access: {principal}")
                            
                            # Check for overly broad actions
                            if isinstance(actions, str):
                                actions = [actions]
                            
                            if 'kms:*' in actions:
                                issues.append("Policy allows all KMS actions")
                    
                    if issues:
                        return CheckResult(
                            check_id="KMS.2",
                            name="KMS Key Policy",
                            status=CheckStatus.NEED_REVIEW,
                            severity=config.severity,
                            description="KMS key policy may be overly permissive",
                            evidence=f"Policy issues: {'; '.join(issues)}",
                            remediation="Review and restrict KMS key policy permissions",
                            resource_id=key_id
                        )
                    else:
                        return CheckResult(
                            check_id="KMS.2",
                            name="KMS Key Policy",
                            status=CheckStatus.OK,
                            severity=config.severity,
                            description="KMS key policy appears secure",
                            evidence="No obvious policy issues found",
                            remediation=None,
                            resource_id=key_id
                        )
                
                except json.JSONDecodeError:
                    return CheckResult(
                        check_id="KMS.2",
                        name="KMS Key Policy",
                        status=CheckStatus.ERROR,
                        severity=config.severity,
                        description="Unable to parse KMS key policy",
                        evidence="Policy document is not valid JSON",
                        remediation="Review key policy format",
                        resource_id=key_id
                    )
            
            except ClientError as e:
                if e.response['Error']['Code'] == 'AccessDeniedException':
                    return CheckResult(
                        check_id="KMS.2",
                        name="KMS Key Policy",
                        status=CheckStatus.ERROR,
                        severity=config.severity,
                        description="Cannot access KMS key policy",
                        evidence="Access denied to key policy",
                        remediation="Check permissions to read key policy",
                        resource_id=key_id
                    )
                else:
                    raise
        
        except Exception as e:
            return self.create_error_result("KMS.2", "KMS Key Policy", 
                                          config.severity, key_id, e)
    
    def check_key_usage(self, key: Dict[str, Any], config: CheckConfig) -> CheckResult:
        """Check if KMS key is being used."""
        try:
            key_id = key.get('KeyId', '')
            key_state = key.get('KeyState', '')
            enabled = key.get('Enabled', False)
            
            if key_state == 'PendingDeletion':
                return CheckResult(
                    check_id="KMS.3",
                    name="KMS Key Usage",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="KMS key is pending deletion",
                    evidence=f"Key state: {key_state}",
                    remediation="Review if key deletion is intentional",
                    resource_id=key_id
                )
            elif not enabled:
                return CheckResult(
                    check_id="KMS.3",
                    name="KMS Key Usage",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="KMS key is disabled",
                    evidence=f"Enabled: {enabled}, State: {key_state}",
                    remediation="Consider deleting unused keys to reduce costs",
                    resource_id=key_id
                )
            else:
                return CheckResult(
                    check_id="KMS.3",
                    name="KMS Key Usage",
                    status=CheckStatus.OK,
                    severity=config.severity,
                    description="KMS key is enabled and available",
                    evidence=f"Enabled: {enabled}, State: {key_state}",
                    remediation=None,
                    resource_id=key_id
                )
        
        except Exception as e:
            return self.create_error_result("KMS.3", "KMS Key Usage", 
                                          config.severity, key_id, e)
    
    def run_all_checks(self, keys: List[Dict[str, Any]], config_checks: Dict[str, CheckConfig], region: str = None) -> List[CheckResult]:
        """Run all KMS security checks for given keys.
        
        Args:
            keys: List of KMS key dictionaries
            config_checks: Dictionary of check configurations
            region: AWS region being checked
            
        Returns:
            List of CheckResult objects
        """
        results = []
        
        for key in keys:
            key_id = key.get('KeyId', 'unknown')
            key_manager = key.get('KeyManager', '')
            
            # Skip AWS-managed keys for most checks
            if key_manager == 'AWS':
                continue
            
            self.logger.info(f"Running KMS security checks for key: {key_id}")
            
            # Key rotation check
            if 'key_rotation' in config_checks:
                result = self.check_key_rotation(key, config_checks['key_rotation'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
            
            # Key policy check
            if 'key_policy' in config_checks:
                result = self.check_key_policy(key, config_checks['key_policy'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
            
            # Key usage check
            if 'key_usage' in config_checks:
                result = self.check_key_usage(key, config_checks['key_usage'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
        
        return results