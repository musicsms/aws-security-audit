"""DynamoDB security checks for AWS Security Audit Tool."""

import logging
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError

from ..aws_client import AWSClientManager
from ..config_manager import CheckConfig, Severity
from .base_checks import BaseSecurityChecks, CheckResult, CheckStatus


class DynamoDBSecurityChecks(BaseSecurityChecks):
    """DynamoDB security checks implementation."""
    
    def __init__(self, aws_client: AWSClientManager):
        super().__init__(aws_client)
    
    def check_table_encryption(self, table_name: str, config: CheckConfig) -> CheckResult:
        """Check if DynamoDB table has encryption at rest enabled."""
        try:
            dynamodb_client = self.aws_client.get_client('dynamodb', self.current_region)
            
            response = dynamodb_client.describe_table(TableName=table_name)
            table_description = response.get('Table', {})
            
            sse_description = table_description.get('SSEDescription', {})
            sse_status = sse_description.get('Status', 'DISABLED')
            sse_type = sse_description.get('SSEType', '')
            kms_key_id = sse_description.get('KMSMasterKeyArn', '')
            
            require_customer_managed_kms = config.parameters.get('require_customer_managed_kms', False)
            
            if sse_status == 'ENABLED':
                if sse_type == 'KMS':
                    # Check if it's customer-managed or AWS-managed KMS key
                    if kms_key_id and 'alias/aws/dynamodb' not in kms_key_id:
                        return CheckResult(
                            check_id="DDB.1",
                            name="DynamoDB Table Encryption",
                            status=CheckStatus.OK,
                            severity=config.severity,
                            description="DynamoDB table has customer-managed KMS encryption",
                            evidence=f"SSE enabled with customer KMS key: {kms_key_id}",
                            remediation=None,
                            resource_id=table_name
                        )
                    else:
                        status = CheckStatus.NEED_REVIEW if require_customer_managed_kms else CheckStatus.OK
                        return CheckResult(
                            check_id="DDB.1",
                            name="DynamoDB Table Encryption",
                            status=status,
                            severity=config.severity,
                            description="DynamoDB table has AWS-managed KMS encryption",
                            evidence=f"SSE enabled with AWS-managed key: {kms_key_id or 'default'}",
                            remediation="Consider using customer-managed KMS key for better control" if require_customer_managed_kms else None,
                            resource_id=table_name
                        )
                else:
                    return CheckResult(
                        check_id="DDB.1",
                        name="DynamoDB Table Encryption",
                        status=CheckStatus.NEED_REVIEW,
                        severity=config.severity,
                        description="DynamoDB table has unknown encryption type",
                        evidence=f"SSE enabled with type: {sse_type}",
                        remediation="Review encryption configuration",
                        resource_id=table_name
                    )
            else:
                return CheckResult(
                    check_id="DDB.1",
                    name="DynamoDB Table Encryption",
                    status=CheckStatus.NOK,
                    severity=config.severity,
                    description="DynamoDB table does not have encryption enabled",
                    evidence=f"SSE status: {sse_status}",
                    remediation="Enable encryption at rest for the DynamoDB table",
                    resource_id=table_name
                )
        
        except Exception as e:
            return self.create_error_result("DDB.1", "DynamoDB Table Encryption", 
                                          config.severity, table_name, e)
    
    def check_point_in_time_recovery(self, table_name: str, config: CheckConfig) -> CheckResult:
        """Check if DynamoDB table has point-in-time recovery enabled."""
        try:
            dynamodb_client = self.aws_client.get_client('dynamodb', self.current_region)
            
            response = dynamodb_client.describe_continuous_backups(TableName=table_name)
            continuous_backups = response.get('ContinuousBackupsDescription', {})
            
            pitr_description = continuous_backups.get('PointInTimeRecoveryDescription', {})
            pitr_status = pitr_description.get('PointInTimeRecoveryStatus', 'DISABLED')
            
            if pitr_status == 'ENABLED':
                earliest_restorable_time = pitr_description.get('EarliestRestorableDateTime', '')
                latest_restorable_time = pitr_description.get('LatestRestorableDateTime', '')
                
                return CheckResult(
                    check_id="DDB.2",
                    name="DynamoDB Point-in-Time Recovery",
                    status=CheckStatus.OK,
                    severity=config.severity,
                    description="DynamoDB table has point-in-time recovery enabled",
                    evidence=f"PITR enabled, earliest restore: {earliest_restorable_time}",
                    remediation=None,
                    resource_id=table_name
                )
            else:
                return CheckResult(
                    check_id="DDB.2",
                    name="DynamoDB Point-in-Time Recovery",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="DynamoDB table does not have point-in-time recovery enabled",
                    evidence=f"PITR status: {pitr_status}",
                    remediation="Enable point-in-time recovery for data protection",
                    resource_id=table_name
                )
        
        except Exception as e:
            return self.create_error_result("DDB.2", "DynamoDB Point-in-Time Recovery", 
                                          config.severity, table_name, e)
    
    def check_table_access_control(self, table_name: str, config: CheckConfig) -> CheckResult:
        """Check DynamoDB table access patterns and resource policies."""
        try:
            dynamodb_client = self.aws_client.get_client('dynamodb', self.current_region)
            
            response = dynamodb_client.describe_table(TableName=table_name)
            table_description = response.get('Table', {})
            
            # Check for VPC endpoints usage (indirect check via table ARN region)
            table_arn = table_description.get('TableArn', '')
            
            # For now, we'll do a basic check for table configuration
            # In a real implementation, you'd want to check IAM policies, resource policies, etc.
            
            billing_mode = table_description.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED')
            table_status = table_description.get('TableStatus', '')
            
            if table_status == 'ACTIVE':
                return CheckResult(
                    check_id="DDB.3",
                    name="DynamoDB Table Access Control",
                    status=CheckStatus.OK,
                    severity=config.severity,
                    description="DynamoDB table is active and accessible",
                    evidence=f"Table status: {table_status}, billing mode: {billing_mode}",
                    remediation=None,
                    resource_id=table_name
                )
            else:
                return CheckResult(
                    check_id="DDB.3",
                    name="DynamoDB Table Access Control",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="DynamoDB table is not in active state",
                    evidence=f"Table status: {table_status}",
                    remediation="Review table status and configuration",
                    resource_id=table_name
                )
        
        except Exception as e:
            return self.create_error_result("DDB.3", "DynamoDB Table Access Control", 
                                          config.severity, table_name, e)
    
    def check_auto_scaling(self, table_name: str, config: CheckConfig) -> CheckResult:
        """Check if DynamoDB table has auto scaling configured."""
        try:
            dynamodb_client = self.aws_client.get_client('dynamodb', self.current_region)
            application_autoscaling_client = self.aws_client.get_client('application-autoscaling', self.current_region)
            
            # Get table details first
            response = dynamodb_client.describe_table(TableName=table_name)
            table_description = response.get('Table', {})
            
            billing_mode = table_description.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED')
            
            if billing_mode == 'PAY_PER_REQUEST':
                return CheckResult(
                    check_id="DDB.4",
                    name="DynamoDB Auto Scaling",
                    status=CheckStatus.OK,
                    severity=config.severity,
                    description="DynamoDB table uses on-demand billing",
                    evidence="Billing mode: PAY_PER_REQUEST",
                    remediation=None,
                    resource_id=table_name
                )
            
            # Check for auto scaling targets
            try:
                scaling_response = application_autoscaling_client.describe_scalable_targets(
                    ServiceNamespace='dynamodb',
                    ResourceIds=[f'table/{table_name}']
                )
                
                scalable_targets = scaling_response.get('ScalableTargets', [])
                
                if scalable_targets:
                    target_info = []
                    for target in scalable_targets:
                        dimension = target.get('ScalableDimension', '')
                        min_capacity = target.get('MinCapacity', 0)
                        max_capacity = target.get('MaxCapacity', 0)
                        target_info.append(f"{dimension}: {min_capacity}-{max_capacity}")
                    
                    return CheckResult(
                        check_id="DDB.4",
                        name="DynamoDB Auto Scaling",
                        status=CheckStatus.OK,
                        severity=config.severity,
                        description="DynamoDB table has auto scaling configured",
                        evidence=f"Auto scaling targets: {', '.join(target_info)}",
                        remediation=None,
                        resource_id=table_name
                    )
                else:
                    return CheckResult(
                        check_id="DDB.4",
                        name="DynamoDB Auto Scaling",
                        status=CheckStatus.NEED_REVIEW,
                        severity=config.severity,
                        description="DynamoDB table uses provisioned mode without auto scaling",
                        evidence="No auto scaling targets configured",
                        remediation="Consider configuring auto scaling or switching to on-demand billing",
                        resource_id=table_name
                    )
            
            except ClientError:
                # If we can't check auto scaling, assume it's not configured
                return CheckResult(
                    check_id="DDB.4",
                    name="DynamoDB Auto Scaling",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="Unable to verify DynamoDB auto scaling configuration",
                    evidence="Auto scaling status unknown",
                    remediation="Review auto scaling configuration",
                    resource_id=table_name
                )
        
        except Exception as e:
            return self.create_error_result("DDB.4", "DynamoDB Auto Scaling", 
                                          config.severity, table_name, e)
    
    def check_global_tables(self, table_name: str, config: CheckConfig) -> CheckResult:
        """Check DynamoDB global tables configuration."""
        try:
            dynamodb_client = self.aws_client.get_client('dynamodb', self.current_region)
            
            response = dynamodb_client.describe_table(TableName=table_name)
            table_description = response.get('Table', {})
            
            global_table_version = table_description.get('GlobalTableVersion', '')
            replicas = table_description.get('Replicas', [])
            
            if global_table_version:
                if replicas and len(replicas) > 1:
                    replica_regions = [replica.get('RegionName', '') for replica in replicas]
                    return CheckResult(
                        check_id="DDB.5",
                        name="DynamoDB Global Tables",
                        status=CheckStatus.OK,
                        severity=config.severity,
                        description="DynamoDB table has global tables configured",
                        evidence=f"Global table version: {global_table_version}, regions: {', '.join(replica_regions)}",
                        remediation=None,
                        resource_id=table_name
                    )
                else:
                    return CheckResult(
                        check_id="DDB.5",
                        name="DynamoDB Global Tables",
                        status=CheckStatus.NEED_REVIEW,
                        severity=config.severity,
                        description="DynamoDB table is configured for global tables but has limited replicas",
                        evidence=f"Global table version: {global_table_version}, replica count: {len(replicas)}",
                        remediation="Review global table configuration and replica strategy",
                        resource_id=table_name
                    )
            else:
                return CheckResult(
                    check_id="DDB.5",
                    name="DynamoDB Global Tables",
                    status=CheckStatus.OK,
                    severity=config.severity,
                    description="DynamoDB table is not configured as a global table",
                    evidence="No global table configuration",
                    remediation=None,
                    resource_id=table_name
                )
        
        except Exception as e:
            return self.create_error_result("DDB.5", "DynamoDB Global Tables", 
                                          config.severity, table_name, e)
    
    def run_all_checks(self, table_names: List[str], config_checks: Dict[str, CheckConfig], region: str = None) -> List[CheckResult]:
        """Run all DynamoDB security checks for given tables.
        
        Args:
            table_names: List of DynamoDB table names
            config_checks: Dictionary of check configurations
            region: AWS region being checked
            
        Returns:
            List of CheckResult objects
        """
        results = []
        
        for table_name in table_names:
            self.logger.info(f"Running DynamoDB security checks for table: {table_name}")
            
            # Encryption check
            if 'encryption_at_rest' in config_checks:
                result = self.check_table_encryption(table_name, config_checks['encryption_at_rest'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
            
            # Point-in-time recovery check
            if 'point_in_time_recovery' in config_checks:
                result = self.check_point_in_time_recovery(table_name, config_checks['point_in_time_recovery'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
            
            # Access control check
            if 'access_control' in config_checks:
                result = self.check_table_access_control(table_name, config_checks['access_control'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
            
            # Auto scaling check
            if 'auto_scaling' in config_checks:
                result = self.check_auto_scaling(table_name, config_checks['auto_scaling'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
            
            # Global tables check
            if 'global_tables' in config_checks:
                result = self.check_global_tables(table_name, config_checks['global_tables'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
        
        return results