"""EC2 security checks for AWS Security Audit Tool."""

import logging
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError

from ..aws_client import AWSClientManager
from ..config_manager import CheckConfig, Severity
from .base_checks import BaseSecurityChecks, CheckResult, CheckStatus


class EC2SecurityChecks(BaseSecurityChecks):
    """EC2 security checks implementation."""
    
    def __init__(self, aws_client: AWSClientManager):
        super().__init__(aws_client)
    
    def check_instance_imds_v2(self, instance: Dict[str, Any], config: CheckConfig) -> CheckResult:
        """Check if EC2 instance requires IMDSv2."""
        try:
            instance_id = instance.get('InstanceId', '')
            metadata_options = instance.get('MetadataOptions', {})
            
            http_tokens = metadata_options.get('HttpTokens', 'optional')
            http_put_response_hop_limit = metadata_options.get('HttpPutResponseHopLimit', 1)
            http_endpoint = metadata_options.get('HttpEndpoint', 'enabled')
            
            require_imds_v2 = config.parameters.get('require_imds_v2', True)
            
            if http_tokens == 'required':
                return CheckResult(
                    check_id="EC2.1",
                    name="Instance Metadata Service v2",
                    status=CheckStatus.OK,
                    severity=config.severity,
                    description="EC2 instance requires IMDSv2",
                    evidence=f"HttpTokens=required, HttpEndpoint={http_endpoint}",
                    remediation=None,
                    resource_id=instance_id
                )
            elif http_tokens == 'optional':
                status = CheckStatus.NOK if require_imds_v2 else CheckStatus.NEED_REVIEW
                return CheckResult(
                    check_id="EC2.1",
                    name="Instance Metadata Service v2",
                    status=status,
                    severity=config.severity,
                    description="EC2 instance allows IMDSv1",
                    evidence=f"HttpTokens=optional, HttpEndpoint={http_endpoint}",
                    remediation="Configure instance to require IMDSv2 tokens",
                    resource_id=instance_id
                )
            else:
                return CheckResult(
                    check_id="EC2.1",
                    name="Instance Metadata Service v2",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="EC2 instance has unknown IMDS configuration",
                    evidence=f"HttpTokens={http_tokens}, HttpEndpoint={http_endpoint}",
                    remediation="Review and configure IMDS settings",
                    resource_id=instance_id
                )
        
        except Exception as e:
            return self.create_error_result("EC2.1", "Instance Metadata Service v2", 
                                          config.severity, instance_id, e)
    
    def check_instance_termination_protection(self, instance: Dict[str, Any], config: CheckConfig) -> CheckResult:
        """Check if EC2 instance has termination protection enabled."""
        try:
            instance_id = instance.get('InstanceId', '')
            
            # Check if instance has termination protection via describe_instance_attribute
            ec2_client = self.aws_client.get_client('ec2', self.current_region)
            
            try:
                response = ec2_client.describe_instance_attribute(
                    InstanceId=instance_id,
                    Attribute='disableApiTermination'
                )
                
                termination_protection = response.get('DisableApiTermination', {}).get('Value', False)
                
                # Check if this is a critical instance that should be protected
                instance_tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                is_critical = any(tag.lower() in ['production', 'critical', 'protected'] 
                                for tag in instance_tags.values())
                
                if termination_protection:
                    return CheckResult(
                        check_id="EC2.2",
                        name="Instance Termination Protection",
                        status=CheckStatus.OK,
                        severity=config.severity,
                        description="EC2 instance has termination protection enabled",
                        evidence="DisableApiTermination=True",
                        remediation=None,
                        resource_id=instance_id
                    )
                else:
                    status = CheckStatus.NOK if is_critical else CheckStatus.NEED_REVIEW
                    return CheckResult(
                        check_id="EC2.2",
                        name="Instance Termination Protection",
                        status=status,
                        severity=config.severity,
                        description="EC2 instance has termination protection disabled",
                        evidence="DisableApiTermination=False",
                        remediation="Enable termination protection for critical instances",
                        resource_id=instance_id
                    )
            
            except ClientError as e:
                if e.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
                    return CheckResult(
                        check_id="EC2.2",
                        name="Instance Termination Protection",
                        status=CheckStatus.ERROR,
                        severity=config.severity,
                        description="EC2 instance not found",
                        evidence="Instance does not exist",
                        remediation="Verify instance ID and permissions",
                        resource_id=instance_id
                    )
                else:
                    raise
        
        except Exception as e:
            return self.create_error_result("EC2.2", "Instance Termination Protection", 
                                          config.severity, instance_id, e)
    
    def check_instance_monitoring(self, instance: Dict[str, Any], config: CheckConfig) -> CheckResult:
        """Check if EC2 instance has detailed monitoring enabled."""
        try:
            instance_id = instance.get('InstanceId', '')
            monitoring = instance.get('Monitoring', {})
            monitoring_state = monitoring.get('State', 'disabled')
            
            if monitoring_state == 'enabled':
                return CheckResult(
                    check_id="EC2.3",
                    name="Instance Monitoring",
                    status=CheckStatus.OK,
                    severity=config.severity,
                    description="EC2 instance has detailed monitoring enabled",
                    evidence=f"Monitoring state: {monitoring_state}",
                    remediation=None,
                    resource_id=instance_id
                )
            else:
                return CheckResult(
                    check_id="EC2.3",
                    name="Instance Monitoring",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="EC2 instance has basic monitoring only",
                    evidence=f"Monitoring state: {monitoring_state}",
                    remediation="Consider enabling detailed monitoring for better visibility",
                    resource_id=instance_id
                )
        
        except Exception as e:
            return self.create_error_result("EC2.3", "Instance Monitoring", 
                                          config.severity, instance_id, e)
    
    def check_ebs_encryption(self, instance: Dict[str, Any], config: CheckConfig) -> CheckResult:
        """Check if EC2 instance EBS volumes are encrypted."""
        try:
            instance_id = instance.get('InstanceId', '')
            block_device_mappings = instance.get('BlockDeviceMappings', [])
            
            if not block_device_mappings:
                return CheckResult(
                    check_id="EC2.4",
                    name="EBS Volume Encryption",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="EC2 instance has no EBS volumes",
                    evidence="No block device mappings found",
                    remediation="Instance may be using instance store volumes",
                    resource_id=instance_id
                )
            
            ec2_client = self.aws_client.get_client('ec2', self.current_region)
            unencrypted_volumes = []
            encrypted_volumes = []
            
            volume_details = []
            
            for mapping in block_device_mappings:
                ebs = mapping.get('Ebs', {})
                volume_id = ebs.get('VolumeId', '')
                
                if volume_id:
                    try:
                        volume_response = ec2_client.describe_volumes(VolumeIds=[volume_id])
                        volumes = volume_response.get('Volumes', [])
                        
                        if volumes:
                            volume = volumes[0]
                            encrypted = volume.get('Encrypted', False)
                            
                            volume_details.append({
                                'volume_id': volume_id,
                                'encrypted': encrypted,
                                'volume_data': volume
                            })
                            
                            if encrypted:
                                encrypted_volumes.append(volume_id)
                            else:
                                unencrypted_volumes.append(volume_id)
                    
                    except ClientError as e:
                        if e.response['Error']['Code'] != 'InvalidVolume.NotFound':
                            raise
            
            # Create raw evidence
            raw_evidence = {
                'instance_metadata': instance,
                'block_device_mappings': block_device_mappings,
                'volume_details': volume_details,
                'api_call': 'describe_volumes'
            }
            
            if unencrypted_volumes:
                return CheckResult(
                    check_id="EC2.4",
                    name="EBS Volume Encryption",
                    status=CheckStatus.NOK,
                    severity=config.severity,
                    description="EC2 instance has unencrypted EBS volumes",
                    evidence=f"Unencrypted volumes: {', '.join(unencrypted_volumes)}",
                    remediation="Encrypt EBS volumes or create encrypted snapshots and replace",
                    resource_id=instance_id,
                    raw_evidence=raw_evidence
                )
            elif encrypted_volumes:
                return CheckResult(
                    check_id="EC2.4",
                    name="EBS Volume Encryption",
                    status=CheckStatus.OK,
                    severity=config.severity,
                    description="EC2 instance has all EBS volumes encrypted",
                    evidence=f"Encrypted volumes: {', '.join(encrypted_volumes)}",
                    remediation=None,
                    resource_id=instance_id,
                    raw_evidence=raw_evidence
                )
            else:
                return CheckResult(
                    check_id="EC2.4",
                    name="EBS Volume Encryption",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="EC2 instance volume encryption status unknown",
                    evidence="Unable to determine volume encryption status",
                    remediation="Check volume permissions and configuration",
                    resource_id=instance_id,
                    raw_evidence=raw_evidence
                )
        
        except Exception as e:
            return self.create_error_result("EC2.4", "EBS Volume Encryption", 
                                          config.severity, instance_id, e, 
                                          region=self.current_region)
    
    def run_all_checks(self, instances: List[Dict[str, Any]], config_checks: Dict[str, CheckConfig], region: str = None) -> List[CheckResult]:
        """Run all EC2 security checks for given instances.
        
        Args:
            instances: List of EC2 instance dictionaries
            config_checks: Dictionary of check configurations
            region: AWS region being checked
            
        Returns:
            List of CheckResult objects
        """
        results = []
        
        for instance in instances:
            instance_id = instance.get('InstanceId', 'unknown')
            self.logger.info(f"Running EC2 security checks for instance: {instance_id}")
            
            # IMDSv2 check
            if 'imds_v2' in config_checks:
                result = self.check_instance_imds_v2(instance, config_checks['imds_v2'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
            
            # Termination protection check
            if 'termination_protection' in config_checks:
                result = self.check_instance_termination_protection(instance, config_checks['termination_protection'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
            
            # Monitoring check
            if 'monitoring' in config_checks:
                result = self.check_instance_monitoring(instance, config_checks['monitoring'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
            
            # EBS encryption check
            if 'ebs_encryption' in config_checks:
                result = self.check_ebs_encryption(instance, config_checks['ebs_encryption'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
        
        return results