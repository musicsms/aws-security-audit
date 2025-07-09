"""Load Balancer security checks for AWS Security Audit Tool."""

import logging
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError

from ..aws_client import AWSClientManager
from ..config_manager import CheckConfig, Severity
from .base_checks import BaseSecurityChecks, CheckResult, CheckStatus


class LoadBalancerSecurityChecks(BaseSecurityChecks):
    """Load Balancer security checks implementation."""
    
    def __init__(self, aws_client: AWSClientManager):
        super().__init__(aws_client)
    
    def check_ssl_configuration(self, load_balancer: Dict[str, Any], lb_type: str, config: CheckConfig) -> CheckResult:
        """Check load balancer SSL/TLS configuration."""
        try:
            if lb_type == 'elbv2':
                lb_arn = load_balancer.get('LoadBalancerArn', '')
                lb_name = load_balancer.get('LoadBalancerName', '')
                lb_scheme = load_balancer.get('Scheme', '')
                
                elbv2_client = self.aws_client.get_client('elbv2')
                
                # Get listeners for this load balancer
                response = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)
                listeners = response.get('Listeners', [])
                
                # Create raw evidence
                raw_evidence = {
                    'load_balancer_metadata': load_balancer,
                    'listeners_response': response,
                    'api_call': 'describe_listeners',
                    'parameters': {'LoadBalancerArn': lb_arn}
                }
                
                https_listeners = []
                http_listeners = []
                ssl_policies = []
                
                for listener in listeners:
                    protocol = listener.get('Protocol', '')
                    port = listener.get('Port', 0)
                    
                    if protocol in ['HTTPS', 'TLS']:
                        https_listeners.append(f"{protocol}:{port}")
                        ssl_policy = listener.get('SslPolicy', '')
                        if ssl_policy:
                            ssl_policies.append(ssl_policy)
                    elif protocol in ['HTTP', 'TCP']:
                        http_listeners.append(f"{protocol}:{port}")
                
                minimum_tls_version = config.parameters.get('minimum_tls_version', '1.2')
                
                if https_listeners and not http_listeners:
                    # Check SSL policies for security
                    weak_policies = []
                    for policy in ssl_policies:
                        if 'TLSv1' in policy and minimum_tls_version == '1.2':
                            weak_policies.append(policy)
                    
                    if weak_policies:
                        return CheckResult(
                            check_id="LB.1",
                            name="Load Balancer SSL Configuration",
                            status=CheckStatus.NEED_REVIEW,
                            severity=config.severity,
                            description="Load balancer uses HTTPS but has weak SSL policies",
                            evidence=f"HTTPS listeners: {', '.join(https_listeners)}, Weak policies: {', '.join(weak_policies)}",
                            remediation="Update SSL policies to use stronger TLS versions",
                            resource_id=lb_name,
                            raw_evidence=raw_evidence
                        )
                    else:
                        return CheckResult(
                            check_id="LB.1",
                            name="Load Balancer SSL Configuration",
                            status=CheckStatus.OK,
                            severity=config.severity,
                            description="Load balancer has secure HTTPS configuration",
                            evidence=f"HTTPS listeners: {', '.join(https_listeners)}, SSL policies: {', '.join(ssl_policies)}",
                            remediation=None,
                            resource_id=lb_name,
                            raw_evidence=raw_evidence
                        )
                elif https_listeners and http_listeners:
                    return CheckResult(
                        check_id="LB.1",
                        name="Load Balancer SSL Configuration",
                        status=CheckStatus.NEED_REVIEW,
                        severity=config.severity,
                        description="Load balancer has both HTTP and HTTPS listeners",
                        evidence=f"HTTPS: {', '.join(https_listeners)}, HTTP: {', '.join(http_listeners)}",
                        remediation="Consider redirecting HTTP to HTTPS or removing HTTP listeners",
                        resource_id=lb_name,
                        raw_evidence=raw_evidence
                    )
                else:
                    return CheckResult(
                        check_id="LB.1",
                        name="Load Balancer SSL Configuration",
                        status=CheckStatus.NOK,
                        severity=config.severity,
                        description="Load balancer does not have HTTPS listeners configured",
                        evidence=f"HTTP listeners: {', '.join(http_listeners) if http_listeners else 'None'}",
                        remediation="Configure HTTPS listeners with appropriate SSL certificates",
                        resource_id=lb_name,
                        raw_evidence=raw_evidence
                    )
            
            elif lb_type == 'elb':
                lb_name = load_balancer.get('LoadBalancerName', '')
                listeners = load_balancer.get('ListenerDescriptions', [])
                
                # Create raw evidence
                raw_evidence = {
                    'load_balancer_metadata': load_balancer,
                    'listener_descriptions': listeners,
                    'api_call': 'describe_load_balancers',
                    'lb_type': 'elb'
                }
                
                https_listeners = []
                http_listeners = []
                
                for listener_desc in listeners:
                    listener = listener_desc.get('Listener', {})
                    protocol = listener.get('Protocol', '')
                    port = listener.get('LoadBalancerPort', 0)
                    
                    if protocol in ['HTTPS', 'SSL']:
                        https_listeners.append(f"{protocol}:{port}")
                    elif protocol in ['HTTP', 'TCP']:
                        http_listeners.append(f"{protocol}:{port}")
                
                if https_listeners and not http_listeners:
                    return CheckResult(
                        check_id="LB.1",
                        name="Load Balancer SSL Configuration",
                        status=CheckStatus.OK,
                        severity=config.severity,
                        description="Classic Load Balancer has HTTPS configuration",
                        evidence=f"HTTPS listeners: {', '.join(https_listeners)}",
                        remediation=None,
                        resource_id=lb_name,
                        raw_evidence=raw_evidence
                    )
                elif https_listeners and http_listeners:
                    return CheckResult(
                        check_id="LB.1",
                        name="Load Balancer SSL Configuration",
                        status=CheckStatus.NEED_REVIEW,
                        severity=config.severity,
                        description="Classic Load Balancer has both HTTP and HTTPS listeners",
                        evidence=f"HTTPS: {', '.join(https_listeners)}, HTTP: {', '.join(http_listeners)}",
                        remediation="Consider using only HTTPS listeners",
                        resource_id=lb_name,
                        raw_evidence=raw_evidence
                    )
                else:
                    return CheckResult(
                        check_id="LB.1",
                        name="Load Balancer SSL Configuration",
                        status=CheckStatus.NOK,
                        severity=config.severity,
                        description="Classic Load Balancer does not have HTTPS listeners",
                        evidence=f"HTTP listeners: {', '.join(http_listeners) if http_listeners else 'None'}",
                        remediation="Configure HTTPS listeners with SSL certificates",
                        resource_id=lb_name,
                        raw_evidence=raw_evidence
                    )
        
        except Exception as e:
            lb_name = load_balancer.get('LoadBalancerName', 'unknown')
            return self.create_error_result("LB.1", "Load Balancer SSL Configuration", 
                                          config.severity, lb_name, e,
                                          raw_evidence={'load_balancer_metadata': load_balancer})
    
    def check_access_logs(self, load_balancer: Dict[str, Any], lb_type: str, config: CheckConfig) -> CheckResult:
        """Check if load balancer has access logging enabled."""
        try:
            if lb_type == 'elbv2':
                lb_arn = load_balancer.get('LoadBalancerArn', '')
                lb_name = load_balancer.get('LoadBalancerName', '')
                
                elbv2_client = self.aws_client.get_client('elbv2')
                
                # Get load balancer attributes
                response = elbv2_client.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
                attributes = response.get('Attributes', [])
                
                # Create raw evidence
                raw_evidence = {
                    'load_balancer_metadata': load_balancer,
                    'attributes_response': response,
                    'api_call': 'describe_load_balancer_attributes',
                    'parameters': {'LoadBalancerArn': lb_arn}
                }
                
                access_logs_enabled = False
                s3_bucket = ''
                
                for attr in attributes:
                    key = attr.get('Key', '')
                    value = attr.get('Value', '')
                    
                    if key == 'access_logs.s3.enabled':
                        access_logs_enabled = value.lower() == 'true'
                    elif key == 'access_logs.s3.bucket':
                        s3_bucket = value
                
                if access_logs_enabled and s3_bucket:
                    return CheckResult(
                        check_id="LB.2",
                        name="Load Balancer Access Logs",
                        status=CheckStatus.OK,
                        severity=config.severity,
                        description="Load balancer has access logging enabled",
                        evidence=f"Access logs enabled, S3 bucket: {s3_bucket}",
                        remediation=None,
                        resource_id=lb_name,
                        raw_evidence=raw_evidence
                    )
                else:
                    return CheckResult(
                        check_id="LB.2",
                        name="Load Balancer Access Logs",
                        status=CheckStatus.NEED_REVIEW,
                        severity=config.severity,
                        description="Load balancer does not have access logging enabled",
                        evidence=f"Access logs enabled: {access_logs_enabled}, S3 bucket: {s3_bucket}",
                        remediation="Enable access logging to S3 for monitoring and troubleshooting",
                        resource_id=lb_name,
                        raw_evidence=raw_evidence
                    )
            
            elif lb_type == 'elb':
                lb_name = load_balancer.get('LoadBalancerName', '')
                
                elb_client = self.aws_client.get_client('elb')
                
                # Get load balancer attributes
                response = elb_client.describe_load_balancer_attributes(LoadBalancerName=lb_name)
                attributes = response.get('LoadBalancerAttributes', {})
                
                # Create raw evidence
                raw_evidence = {
                    'load_balancer_metadata': load_balancer,
                    'attributes_response': response,
                    'api_call': 'describe_load_balancer_attributes',
                    'parameters': {'LoadBalancerName': lb_name}
                }
                
                access_log = attributes.get('AccessLog', {})
                enabled = access_log.get('Enabled', False)
                s3_bucket_name = access_log.get('S3BucketName', '')
                
                if enabled and s3_bucket_name:
                    return CheckResult(
                        check_id="LB.2",
                        name="Load Balancer Access Logs",
                        status=CheckStatus.OK,
                        severity=config.severity,
                        description="Classic Load Balancer has access logging enabled",
                        evidence=f"Access logs enabled, S3 bucket: {s3_bucket_name}",
                        remediation=None,
                        resource_id=lb_name,
                        raw_evidence=raw_evidence
                    )
                else:
                    return CheckResult(
                        check_id="LB.2",
                        name="Load Balancer Access Logs",
                        status=CheckStatus.NEED_REVIEW,
                        severity=config.severity,
                        description="Classic Load Balancer does not have access logging enabled",
                        evidence=f"Access logs enabled: {enabled}, S3 bucket: {s3_bucket_name}",
                        remediation="Enable access logging to S3 for monitoring",
                        resource_id=lb_name,
                        raw_evidence=raw_evidence
                    )
        
        except Exception as e:
            lb_name = load_balancer.get('LoadBalancerName', 'unknown')
            return self.create_error_result("LB.2", "Load Balancer Access Logs", 
                                          config.severity, lb_name, e,
                                          raw_evidence={'load_balancer_metadata': load_balancer})
    
    def check_deletion_protection(self, load_balancer: Dict[str, Any], lb_type: str, config: CheckConfig) -> CheckResult:
        """Check if load balancer has deletion protection enabled."""
        try:
            if lb_type == 'elbv2':
                lb_arn = load_balancer.get('LoadBalancerArn', '')
                lb_name = load_balancer.get('LoadBalancerName', '')
                
                elbv2_client = self.aws_client.get_client('elbv2')
                
                # Get load balancer attributes
                response = elbv2_client.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
                attributes = response.get('Attributes', [])
                
                deletion_protection_enabled = False
                
                for attr in attributes:
                    key = attr.get('Key', '')
                    value = attr.get('Value', '')
                    
                    if key == 'deletion_protection.enabled':
                        deletion_protection_enabled = value.lower() == 'true'
                        break
                
                if deletion_protection_enabled:
                    return CheckResult(
                        check_id="LB.3",
                        name="Load Balancer Deletion Protection",
                        status=CheckStatus.OK,
                        severity=config.severity,
                        description="Load balancer has deletion protection enabled",
                        evidence="Deletion protection enabled",
                        remediation=None,
                        resource_id=lb_name
                    )
                else:
                    return CheckResult(
                        check_id="LB.3",
                        name="Load Balancer Deletion Protection",
                        status=CheckStatus.NEED_REVIEW,
                        severity=config.severity,
                        description="Load balancer does not have deletion protection enabled",
                        evidence="Deletion protection disabled",
                        remediation="Enable deletion protection for critical load balancers",
                        resource_id=lb_name
                    )
            
            elif lb_type == 'elb':
                lb_name = load_balancer.get('LoadBalancerName', '')
                
                # Classic Load Balancers don't have deletion protection
                return CheckResult(
                    check_id="LB.3",
                    name="Load Balancer Deletion Protection",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="Classic Load Balancer does not support deletion protection",
                    evidence="ELB (Classic) type",
                    remediation="Consider migrating to Application or Network Load Balancer",
                    resource_id=lb_name
                )
        
        except Exception as e:
            lb_name = load_balancer.get('LoadBalancerName', 'unknown')
            return self.create_error_result("LB.3", "Load Balancer Deletion Protection", 
                                          config.severity, lb_name, e,
                                          raw_evidence={'load_balancer_metadata': load_balancer})
    
    def check_security_groups(self, load_balancer: Dict[str, Any], lb_type: str, config: CheckConfig) -> CheckResult:
        """Check load balancer security group configuration."""
        try:
            if lb_type == 'elbv2':
                lb_name = load_balancer.get('LoadBalancerName', '')
                security_groups = load_balancer.get('SecurityGroups', [])
                lb_type_attr = load_balancer.get('Type', '')
                
                if lb_type_attr == 'network':
                    return CheckResult(
                        check_id="LB.4",
                        name="Load Balancer Security Groups",
                        status=CheckStatus.OK,
                        severity=config.severity,
                        description="Network Load Balancer does not use security groups",
                        evidence="NLB type (uses NACLs instead of security groups)",
                        remediation=None,
                        resource_id=lb_name
                    )
                
                if security_groups:
                    return CheckResult(
                        check_id="LB.4",
                        name="Load Balancer Security Groups",
                        status=CheckStatus.OK,
                        severity=config.severity,
                        description="Load balancer has security groups configured",
                        evidence=f"Security groups: {', '.join(security_groups)}",
                        remediation=None,
                        resource_id=lb_name
                    )
                else:
                    return CheckResult(
                        check_id="LB.4",
                        name="Load Balancer Security Groups",
                        status=CheckStatus.NEED_REVIEW,
                        severity=config.severity,
                        description="Load balancer has no security groups configured",
                        evidence="No security groups assigned",
                        remediation="Configure appropriate security groups for access control",
                        resource_id=lb_name
                    )
            
            elif lb_type == 'elb':
                lb_name = load_balancer.get('LoadBalancerName', '')
                security_groups = load_balancer.get('SecurityGroups', [])
                
                if security_groups:
                    return CheckResult(
                        check_id="LB.4",
                        name="Load Balancer Security Groups",
                        status=CheckStatus.OK,
                        severity=config.severity,
                        description="Classic Load Balancer has security groups configured",
                        evidence=f"Security groups: {', '.join(security_groups)}",
                        remediation=None,
                        resource_id=lb_name
                    )
                else:
                    return CheckResult(
                        check_id="LB.4",
                        name="Load Balancer Security Groups",
                        status=CheckStatus.NEED_REVIEW,
                        severity=config.severity,
                        description="Classic Load Balancer has no security groups configured",
                        evidence="No security groups assigned",
                        remediation="Configure appropriate security groups",
                        resource_id=lb_name
                    )
        
        except Exception as e:
            lb_name = load_balancer.get('LoadBalancerName', 'unknown')
            return self.create_error_result("LB.4", "Load Balancer Security Groups", 
                                          config.severity, lb_name, e,
                                          raw_evidence={'load_balancer_metadata': load_balancer})
    
    def run_all_checks(self, load_balancers: Dict[str, List[Dict[str, Any]]], config_checks: Dict[str, CheckConfig], region: str = None) -> List[CheckResult]:
        """Run all Load Balancer security checks.
        
        Args:
            load_balancers: Dictionary containing 'elbv2' and 'elb' load balancer lists
            config_checks: Dictionary of check configurations
            region: AWS region being checked
            
        Returns:
            List of CheckResult objects
        """
        results = []
        
        # Check ALB/NLB (ELBv2)
        for lb in load_balancers.get('elbv2', []):
            lb_name = lb.get('LoadBalancerName', 'unknown')
            self.logger.info(f"Running ALB/NLB security checks for: {lb_name}")
            
            # SSL configuration check
            if 'ssl_configuration' in config_checks:
                result = self.check_ssl_configuration(lb, 'elbv2', config_checks['ssl_configuration'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
            
            # Access logs check
            if 'access_logs' in config_checks:
                result = self.check_access_logs(lb, 'elbv2', config_checks['access_logs'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
            
            # Deletion protection check
            if 'deletion_protection' in config_checks:
                result = self.check_deletion_protection(lb, 'elbv2', config_checks['deletion_protection'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
            
            # Security groups check
            if 'security_groups' in config_checks:
                result = self.check_security_groups(lb, 'elbv2', config_checks['security_groups'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
        
        # Check Classic Load Balancers (ELB)
        for lb in load_balancers.get('elb', []):
            lb_name = lb.get('LoadBalancerName', 'unknown')
            self.logger.info(f"Running Classic ELB security checks for: {lb_name}")
            
            # SSL configuration check
            if 'ssl_configuration' in config_checks:
                result = self.check_ssl_configuration(lb, 'elb', config_checks['ssl_configuration'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
            
            # Access logs check
            if 'access_logs' in config_checks:
                result = self.check_access_logs(lb, 'elb', config_checks['access_logs'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
            
            # Deletion protection check
            if 'deletion_protection' in config_checks:
                result = self.check_deletion_protection(lb, 'elb', config_checks['deletion_protection'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
            
            # Security groups check
            if 'security_groups' in config_checks:
                result = self.check_security_groups(lb, 'elb', config_checks['security_groups'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
        
        return results