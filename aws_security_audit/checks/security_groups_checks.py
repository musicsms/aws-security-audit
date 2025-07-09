"""Security Groups security checks for AWS Security Audit Tool."""

import logging
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError

from ..aws_client import AWSClientManager
from ..config_manager import CheckConfig, Severity
from .base_checks import BaseSecurityChecks, CheckResult, CheckStatus


class SecurityGroupsChecks(BaseSecurityChecks):
    """Security Groups security checks implementation."""
    
    def __init__(self, aws_client: AWSClientManager):
        super().__init__(aws_client)
    
    def check_unrestricted_ingress(self, security_group: Dict[str, Any], config: CheckConfig) -> CheckResult:
        """Check for unrestricted ingress rules in security groups."""
        try:
            group_id = security_group.get('GroupId', '')
            group_name = security_group.get('GroupName', '')
            ingress_rules = security_group.get('IpPermissions', [])
            
            unrestricted_rules = []
            ssh_rdp_issues = []
            
            for rule in ingress_rules:
                from_port = rule.get('FromPort', 0)
                to_port = rule.get('ToPort', 0)
                ip_protocol = rule.get('IpProtocol', '')
                
                # Check for unrestricted access (0.0.0.0/0)
                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', '')
                    if cidr == '0.0.0.0/0':
                        if ip_protocol == '-1':  # All protocols
                            unrestricted_rules.append(f"All traffic from {cidr}")
                        elif from_port == 0 and to_port == 65535:
                            unrestricted_rules.append(f"All {ip_protocol} ports from {cidr}")
                        else:
                            port_range = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
                            unrestricted_rules.append(f"Port {port_range} ({ip_protocol}) from {cidr}")
                            
                            # Check for SSH (22) and RDP (3389) specifically
                            if from_port <= 22 <= to_port:
                                ssh_rdp_issues.append(f"SSH (22) open to {cidr}")
                            if from_port <= 3389 <= to_port:
                                ssh_rdp_issues.append(f"RDP (3389) open to {cidr}")
                
                # Check for unrestricted IPv6 access
                for ipv6_range in rule.get('Ipv6Ranges', []):
                    cidr = ipv6_range.get('CidrIpv6', '')
                    if cidr == '::/0':
                        port_range = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
                        unrestricted_rules.append(f"Port {port_range} ({ip_protocol}) from {cidr}")
            
            allow_unrestricted_ssh = config.parameters.get('allow_unrestricted_ssh', False)
            allow_unrestricted_rdp = config.parameters.get('allow_unrestricted_rdp', False)
            
            if ssh_rdp_issues and not (allow_unrestricted_ssh or allow_unrestricted_rdp):
                return CheckResult(
                    check_id="SG.1",
                    name="Security Group Unrestricted Access",
                    status=CheckStatus.NOK,
                    severity=Severity.CRITICAL,
                    description="Security group allows unrestricted SSH/RDP access",
                    evidence=f"Critical issues: {', '.join(ssh_rdp_issues)}",
                    remediation="Restrict SSH and RDP access to specific IP ranges",
                    resource_id=group_id
                )
            elif unrestricted_rules:
                return CheckResult(
                    check_id="SG.1",
                    name="Security Group Unrestricted Access",
                    status=CheckStatus.NOK,
                    severity=config.severity,
                    description="Security group has unrestricted ingress rules",
                    evidence=f"Unrestricted rules: {', '.join(unrestricted_rules)}",
                    remediation="Restrict ingress rules to specific IP ranges",
                    resource_id=group_id
                )
            else:
                return CheckResult(
                    check_id="SG.1",
                    name="Security Group Unrestricted Access",
                    status=CheckStatus.OK,
                    severity=config.severity,
                    description="Security group has properly restricted ingress rules",
                    evidence="No unrestricted ingress rules found",
                    remediation=None,
                    resource_id=group_id
                )
        
        except Exception as e:
            return self.create_error_result("SG.1", "Security Group Unrestricted Access", 
                                          config.severity, group_id, e)
    
    def check_overly_permissive_egress(self, security_group: Dict[str, Any], config: CheckConfig) -> CheckResult:
        """Check for overly permissive egress rules in security groups."""
        try:
            group_id = security_group.get('GroupId', '')
            egress_rules = security_group.get('IpPermissionsEgress', [])
            
            unrestricted_egress = []
            
            for rule in egress_rules:
                from_port = rule.get('FromPort', 0)
                to_port = rule.get('ToPort', 0)
                ip_protocol = rule.get('IpProtocol', '')
                
                # Check for unrestricted egress (0.0.0.0/0)
                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', '')
                    if cidr == '0.0.0.0/0':
                        if ip_protocol == '-1':  # All protocols
                            unrestricted_egress.append(f"All traffic to {cidr}")
                        elif from_port == 0 and to_port == 65535:
                            unrestricted_egress.append(f"All {ip_protocol} ports to {cidr}")
                        else:
                            port_range = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
                            unrestricted_egress.append(f"Port {port_range} ({ip_protocol}) to {cidr}")
                
                # Check for unrestricted IPv6 egress
                for ipv6_range in rule.get('Ipv6Ranges', []):
                    cidr = ipv6_range.get('CidrIpv6', '')
                    if cidr == '::/0':
                        port_range = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
                        unrestricted_egress.append(f"Port {port_range} ({ip_protocol}) to {cidr}")
            
            allow_unrestricted_egress = config.parameters.get('allow_unrestricted_egress', True)
            
            if unrestricted_egress and not allow_unrestricted_egress:
                return CheckResult(
                    check_id="SG.2",
                    name="Security Group Egress Rules",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="Security group has unrestricted egress rules",
                    evidence=f"Unrestricted egress: {', '.join(unrestricted_egress)}",
                    remediation="Consider restricting egress rules to required destinations",
                    resource_id=group_id
                )
            else:
                return CheckResult(
                    check_id="SG.2",
                    name="Security Group Egress Rules",
                    status=CheckStatus.OK,
                    severity=config.severity,
                    description="Security group egress rules are acceptable",
                    evidence="Egress rules follow security policy",
                    remediation=None,
                    resource_id=group_id
                )
        
        except Exception as e:
            return self.create_error_result("SG.2", "Security Group Egress Rules", 
                                          config.severity, group_id, e)
    
    def check_unused_security_groups(self, security_groups: List[Dict[str, Any]], config: CheckConfig) -> List[CheckResult]:
        """Check for unused security groups."""
        try:
            ec2_client = self.aws_client.get_client('ec2', self.current_region)
            
            # Get all network interfaces to check security group usage
            try:
                response = ec2_client.describe_network_interfaces()
                network_interfaces = response.get('NetworkInterfaces', [])
            except ClientError:
                # If we can't get network interfaces, skip this check
                return []
            
            # Collect security groups in use
            used_security_groups = set()
            for ni in network_interfaces:
                for sg in ni.get('Groups', []):
                    used_security_groups.add(sg.get('GroupId', ''))
            
            results = []
            
            for sg in security_groups:
                group_id = sg.get('GroupId', '')
                group_name = sg.get('GroupName', '')
                
                # Skip default security groups
                if group_name == 'default':
                    continue
                
                if group_id not in used_security_groups:
                    results.append(CheckResult(
                        check_id="SG.3",
                        name="Unused Security Groups",
                        status=CheckStatus.NEED_REVIEW,
                        severity=config.severity,
                        description="Security group is not in use",
                        evidence=f"Security group {group_name} ({group_id}) is not attached to any resources",
                        remediation="Consider removing unused security groups",
                        resource_id=group_id
                    ))
            
            return results
        
        except Exception as e:
            self.logger.error(f"Error checking unused security groups: {e}")
            return []
    
    def run_all_checks(self, security_groups: List[Dict[str, Any]], config_checks: Dict[str, CheckConfig], region: str = None) -> List[CheckResult]:
        """Run all security group checks.
        
        Args:
            security_groups: List of security group dictionaries
            config_checks: Dictionary of check configurations
            region: AWS region being checked
            
        Returns:
            List of CheckResult objects
        """
        results = []
        
        for sg in security_groups:
            group_id = sg.get('GroupId', 'unknown')
            self.logger.info(f"Running security group checks for: {group_id}")
            
            # Unrestricted ingress check
            if 'unrestricted_ingress' in config_checks:
                result = self.check_unrestricted_ingress(sg, config_checks['unrestricted_ingress'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
            
            # Overly permissive egress check
            if 'overly_permissive_egress' in config_checks:
                result = self.check_overly_permissive_egress(sg, config_checks['overly_permissive_egress'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
        
        # Unused security groups check (run once for all groups)
        if 'unused_security_groups' in config_checks:
            unused_results = self.check_unused_security_groups(security_groups, config_checks['unused_security_groups'])
            for result in unused_results:
                if result:
                    result.region = region or self.current_region
            results.extend(unused_results)
        
        return results