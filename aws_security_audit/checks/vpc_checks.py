"""VPC security checks for AWS Security Audit Tool."""

import logging
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError

from ..aws_client import AWSClientManager
from ..config_manager import CheckConfig, Severity
from .base_checks import BaseSecurityChecks, CheckResult, CheckStatus


class VPCSecurityChecks(BaseSecurityChecks):
    """VPC security checks implementation."""
    
    def __init__(self, aws_client: AWSClientManager):
        super().__init__(aws_client)
    
    def check_vpc_flow_logs(self, vpc: Dict[str, Any], config: CheckConfig) -> CheckResult:
        """Check if VPC has flow logs enabled."""
        try:
            vpc_id = vpc.get('VpcId', '')
            ec2_client = self.aws_client.get_client('ec2', self.current_region)
            
            # Check for flow logs for this VPC
            response = ec2_client.describe_flow_logs(
                Filters=[
                    {
                        'Name': 'resource-id',
                        'Values': [vpc_id]
                    }
                ]
            )
            
            flow_logs = response.get('FlowLogs', [])
            active_flow_logs = [fl for fl in flow_logs if fl.get('FlowLogStatus') == 'ACTIVE']
            
            require_flow_logs = config.parameters.get('require_flow_logs', True)
            
            if active_flow_logs:
                log_destinations = [fl.get('LogDestination', 'CloudWatch') for fl in active_flow_logs]
                return CheckResult(
                    check_id="VPC.1",
                    name="VPC Flow Logs",
                    status=CheckStatus.OK,
                    severity=config.severity,
                    description="VPC has flow logs enabled",
                    evidence=f"Active flow logs: {len(active_flow_logs)}, Destinations: {', '.join(log_destinations)}",
                    remediation=None,
                    resource_id=vpc_id
                )
            else:
                status = CheckStatus.NOK if require_flow_logs else CheckStatus.NEED_REVIEW
                return CheckResult(
                    check_id="VPC.1",
                    name="VPC Flow Logs",
                    status=status,
                    severity=config.severity,
                    description="VPC does not have flow logs enabled",
                    evidence="No active flow logs found",
                    remediation="Enable VPC flow logs to monitor network traffic",
                    resource_id=vpc_id
                )
        
        except Exception as e:
            return self.create_error_result("VPC.1", "VPC Flow Logs", 
                                          config.severity, vpc_id, e)
    
    def check_default_vpc_usage(self, vpc: Dict[str, Any], config: CheckConfig) -> CheckResult:
        """Check if this is a default VPC and if it's being used."""
        try:
            vpc_id = vpc.get('VpcId', '')
            is_default = vpc.get('IsDefault', False)
            
            flag_default_vpc = config.parameters.get('flag_default_vpc_usage', True)
            
            if is_default and flag_default_vpc:
                # Check if default VPC has any instances
                ec2_client = self.aws_client.get_client('ec2', self.current_region)
                
                try:
                    response = ec2_client.describe_instances(
                        Filters=[
                            {
                                'Name': 'vpc-id',
                                'Values': [vpc_id]
                            },
                            {
                                'Name': 'instance-state-name',
                                'Values': ['running', 'pending', 'stopping', 'stopped']
                            }
                        ]
                    )
                    
                    instances = []
                    for reservation in response.get('Reservations', []):
                        instances.extend(reservation.get('Instances', []))
                    
                    if instances:
                        return CheckResult(
                            check_id="VPC.2",
                            name="Default VPC Usage",
                            status=CheckStatus.NEED_REVIEW,
                            severity=config.severity,
                            description="Default VPC is in use",
                            evidence=f"Default VPC contains {len(instances)} instances",
                            remediation="Consider migrating resources to custom VPC and removing default VPC",
                            resource_id=vpc_id
                        )
                    else:
                        return CheckResult(
                            check_id="VPC.2",
                            name="Default VPC Usage",
                            status=CheckStatus.OK,
                            severity=config.severity,
                            description="Default VPC exists but is not in use",
                            evidence="Default VPC has no running instances",
                            remediation="Consider deleting the unused default VPC",
                            resource_id=vpc_id
                        )
                
                except ClientError:
                    # If we can't check instances, just flag the default VPC
                    return CheckResult(
                        check_id="VPC.2",
                        name="Default VPC Usage",
                        status=CheckStatus.NEED_REVIEW,
                        severity=config.severity,
                        description="Default VPC exists",
                        evidence="Default VPC found (unable to check usage)",
                        remediation="Review default VPC usage and consider removal",
                        resource_id=vpc_id
                    )
            
            else:
                return CheckResult(
                    check_id="VPC.2",
                    name="Default VPC Usage",
                    status=CheckStatus.OK,
                    severity=config.severity,
                    description="VPC is a custom VPC",
                    evidence="Not a default VPC",
                    remediation=None,
                    resource_id=vpc_id
                )
        
        except Exception as e:
            return self.create_error_result("VPC.2", "Default VPC Usage", 
                                          config.severity, vpc_id, e)
    
    def check_vpc_dns_settings(self, vpc: Dict[str, Any], config: CheckConfig) -> CheckResult:
        """Check VPC DNS resolution and DNS hostnames settings."""
        try:
            vpc_id = vpc.get('VpcId', '')
            ec2_client = self.aws_client.get_client('ec2', self.current_region)
            
            # Get DNS attributes
            dns_support_response = ec2_client.describe_vpc_attribute(
                VpcId=vpc_id,
                Attribute='enableDnsSupport'
            )
            
            dns_hostnames_response = ec2_client.describe_vpc_attribute(
                VpcId=vpc_id,
                Attribute='enableDnsHostnames'
            )
            
            dns_support = dns_support_response.get('EnableDnsSupport', {}).get('Value', False)
            dns_hostnames = dns_hostnames_response.get('EnableDnsHostnames', {}).get('Value', False)
            
            if dns_support and dns_hostnames:
                return CheckResult(
                    check_id="VPC.3",
                    name="VPC DNS Settings",
                    status=CheckStatus.OK,
                    severity=config.severity,
                    description="VPC has proper DNS settings enabled",
                    evidence=f"DNS support: {dns_support}, DNS hostnames: {dns_hostnames}",
                    remediation=None,
                    resource_id=vpc_id
                )
            elif dns_support and not dns_hostnames:
                return CheckResult(
                    check_id="VPC.3",
                    name="VPC DNS Settings",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="VPC has DNS support but not DNS hostnames enabled",
                    evidence=f"DNS support: {dns_support}, DNS hostnames: {dns_hostnames}",
                    remediation="Consider enabling DNS hostnames for better name resolution",
                    resource_id=vpc_id
                )
            else:
                return CheckResult(
                    check_id="VPC.3",
                    name="VPC DNS Settings",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="VPC has DNS issues",
                    evidence=f"DNS support: {dns_support}, DNS hostnames: {dns_hostnames}",
                    remediation="Enable DNS support and DNS hostnames for proper name resolution",
                    resource_id=vpc_id
                )
        
        except Exception as e:
            return self.create_error_result("VPC.3", "VPC DNS Settings", 
                                          config.severity, vpc_id, e)
    
    def check_vpc_endpoints(self, vpc: Dict[str, Any], config: CheckConfig) -> CheckResult:
        """Check if VPC has endpoints configured for AWS services."""
        try:
            vpc_id = vpc.get('VpcId', '')
            ec2_client = self.aws_client.get_client('ec2', self.current_region)
            
            # Get VPC endpoints
            response = ec2_client.describe_vpc_endpoints(
                Filters=[
                    {
                        'Name': 'vpc-id',
                        'Values': [vpc_id]
                    }
                ]
            )
            
            vpc_endpoints = response.get('VpcEndpoints', [])
            active_endpoints = [ep for ep in vpc_endpoints if ep.get('State') == 'available']
            
            endpoint_services = [ep.get('ServiceName', '').split('.')[-1] for ep in active_endpoints]
            
            if active_endpoints:
                return CheckResult(
                    check_id="VPC.4",
                    name="VPC Endpoints",
                    status=CheckStatus.OK,
                    severity=config.severity,
                    description="VPC has endpoints configured",
                    evidence=f"VPC endpoints: {len(active_endpoints)}, Services: {', '.join(endpoint_services)}",
                    remediation=None,
                    resource_id=vpc_id
                )
            else:
                return CheckResult(
                    check_id="VPC.4",
                    name="VPC Endpoints",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="VPC has no endpoints configured",
                    evidence="No VPC endpoints found",
                    remediation="Consider configuring VPC endpoints for AWS services to improve security and performance",
                    resource_id=vpc_id
                )
        
        except Exception as e:
            return self.create_error_result("VPC.4", "VPC Endpoints", 
                                          config.severity, vpc_id, e)
    
    def run_all_checks(self, vpcs: List[Dict[str, Any]], config_checks: Dict[str, CheckConfig], region: str = None) -> List[CheckResult]:
        """Run all VPC security checks for given VPCs.
        
        Args:
            vpcs: List of VPC dictionaries
            config_checks: Dictionary of check configurations
            region: AWS region being checked
            
        Returns:
            List of CheckResult objects
        """
        results = []
        
        for vpc in vpcs:
            vpc_id = vpc.get('VpcId', 'unknown')
            self.logger.info(f"Running VPC security checks for VPC: {vpc_id}")
            
            # Flow logs check
            if 'flow_logs' in config_checks:
                result = self.check_vpc_flow_logs(vpc, config_checks['flow_logs'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
            
            # Default VPC usage check
            if 'default_vpc' in config_checks:
                result = self.check_default_vpc_usage(vpc, config_checks['default_vpc'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
            
            # DNS settings check
            if 'dns_settings' in config_checks:
                result = self.check_vpc_dns_settings(vpc, config_checks['dns_settings'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
            
            # VPC endpoints check
            if 'vpc_endpoints' in config_checks:
                result = self.check_vpc_endpoints(vpc, config_checks['vpc_endpoints'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
        
        return results