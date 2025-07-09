"""EKS security checks for AWS Security Audit Tool."""

import logging
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError

from ..aws_client import AWSClientManager
from ..config_manager import CheckConfig, Severity
from .base_checks import BaseSecurityChecks, CheckResult, CheckStatus


class EKSSecurityChecks(BaseSecurityChecks):
    """EKS security checks implementation."""
    
    def __init__(self, aws_client: AWSClientManager):
        super().__init__(aws_client)
    
    def check_cluster_endpoint_access(self, cluster_name: str, config: CheckConfig) -> CheckResult:
        """Check EKS cluster endpoint access configuration."""
        try:
            eks_client = self.aws_client.get_client('eks', self.current_region)
            
            response = eks_client.describe_cluster(name=cluster_name)
            cluster = response.get('cluster', {})
            
            # Create raw evidence
            raw_evidence = {
                'cluster_response': response,
                'api_call': 'describe_cluster',
                'parameters': {'name': cluster_name}
            }
            
            endpoint_config = cluster.get('resourcesVpcConfig', {})
            endpoint_private_access = endpoint_config.get('endpointPrivateAccess', False)
            endpoint_public_access = endpoint_config.get('endpointPublicAccess', True)
            public_access_cidrs = endpoint_config.get('publicAccessCidrs', [])
            
            allow_public_endpoint = config.parameters.get('allow_public_endpoint', False)
            
            if endpoint_private_access and not endpoint_public_access:
                return CheckResult(
                    check_id="EKS.1",
                    name="EKS Cluster Endpoint Access",
                    status=CheckStatus.OK,
                    severity=config.severity,
                    description="EKS cluster has private endpoint access only",
                    evidence=f"Private access: {endpoint_private_access}, Public access: {endpoint_public_access}",
                    remediation=None,
                    resource_id=cluster_name,
                    raw_evidence=raw_evidence
                )
            elif endpoint_private_access and endpoint_public_access:
                # Check if public access is restricted
                if public_access_cidrs and '0.0.0.0/0' not in public_access_cidrs:
                    status = CheckStatus.OK if allow_public_endpoint else CheckStatus.NEED_REVIEW
                    return CheckResult(
                        check_id="EKS.1",
                        name="EKS Cluster Endpoint Access",
                        status=status,
                        severity=config.severity,
                        description="EKS cluster has restricted public endpoint access",
                        evidence=f"Private: {endpoint_private_access}, Public: {endpoint_public_access}, CIDRs: {public_access_cidrs}",
                        remediation="Consider using private endpoint only" if not allow_public_endpoint else None,
                        resource_id=cluster_name,
                        raw_evidence=raw_evidence
                    )
                else:
                    return CheckResult(
                        check_id="EKS.1",
                        name="EKS Cluster Endpoint Access",
                        status=CheckStatus.NOK,
                        severity=Severity.HIGH,
                        description="EKS cluster has unrestricted public endpoint access",
                        evidence=f"Public access enabled with unrestricted CIDRs: {public_access_cidrs}",
                        remediation="Restrict public endpoint access or use private endpoint only",
                        resource_id=cluster_name,
                        raw_evidence=raw_evidence
                    )
            elif not endpoint_private_access and endpoint_public_access:
                return CheckResult(
                    check_id="EKS.1",
                    name="EKS Cluster Endpoint Access",
                    status=CheckStatus.NOK,
                    severity=config.severity,
                    description="EKS cluster has public endpoint access only",
                    evidence=f"Private access: {endpoint_private_access}, Public access: {endpoint_public_access}",
                    remediation="Enable private endpoint access and restrict or disable public access",
                    resource_id=cluster_name,
                    raw_evidence=raw_evidence
                )
            else:
                return CheckResult(
                    check_id="EKS.1",
                    name="EKS Cluster Endpoint Access",
                    status=CheckStatus.ERROR,
                    severity=config.severity,
                    description="EKS cluster has no endpoint access configured",
                    evidence=f"Private access: {endpoint_private_access}, Public access: {endpoint_public_access}",
                    remediation="Configure appropriate endpoint access",
                    resource_id=cluster_name,
                    raw_evidence=raw_evidence
                )
        
        except Exception as e:
            return self.create_error_result("EKS.1", "EKS Cluster Endpoint Access", 
                                          config.severity, cluster_name, e,
                                          raw_evidence={'cluster_name': cluster_name})
    
    def check_cluster_logging(self, cluster_name: str, config: CheckConfig) -> CheckResult:
        """Check EKS cluster control plane logging configuration."""
        try:
            eks_client = self.aws_client.get_client('eks', self.current_region)
            
            response = eks_client.describe_cluster(name=cluster_name)
            cluster = response.get('cluster', {})
            
            logging_config = cluster.get('logging', {})
            cluster_logging = logging_config.get('clusterLogging', [])
            
            enabled_log_types = []
            disabled_log_types = []
            
            for log_config in cluster_logging:
                log_types = log_config.get('types', [])
                enabled = log_config.get('enabled', False)
                
                if enabled:
                    enabled_log_types.extend(log_types)
                else:
                    disabled_log_types.extend(log_types)
            
            # Standard log types: api, audit, authenticator, controllerManager, scheduler
            all_log_types = {'api', 'audit', 'authenticator', 'controllerManager', 'scheduler'}
            enabled_set = set(enabled_log_types)
            
            if enabled_set == all_log_types:
                return CheckResult(
                    check_id="EKS.2",
                    name="EKS Cluster Logging",
                    status=CheckStatus.OK,
                    severity=config.severity,
                    description="EKS cluster has all control plane logs enabled",
                    evidence=f"Enabled log types: {', '.join(sorted(enabled_log_types))}",
                    remediation=None,
                    resource_id=cluster_name
                )
            elif enabled_log_types:
                missing_logs = all_log_types - enabled_set
                return CheckResult(
                    check_id="EKS.2",
                    name="EKS Cluster Logging",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="EKS cluster has partial control plane logging",
                    evidence=f"Enabled: {', '.join(sorted(enabled_log_types))}, Missing: {', '.join(sorted(missing_logs))}",
                    remediation="Enable all control plane log types for comprehensive monitoring",
                    resource_id=cluster_name
                )
            else:
                return CheckResult(
                    check_id="EKS.2",
                    name="EKS Cluster Logging",
                    status=CheckStatus.NOK,
                    severity=config.severity,
                    description="EKS cluster has no control plane logging enabled",
                    evidence="No log types enabled",
                    remediation="Enable control plane logging for security monitoring",
                    resource_id=cluster_name
                )
        
        except Exception as e:
            return self.create_error_result("EKS.2", "EKS Cluster Logging", 
                                          config.severity, cluster_name, e,
                                          raw_evidence={'cluster_name': cluster_name})
    
    def check_node_group_security(self, cluster_name: str, config: CheckConfig) -> CheckResult:
        """Check EKS node group security configuration."""
        try:
            eks_client = self.aws_client.get_client('eks', self.current_region)
            
            # List node groups for the cluster
            response = eks_client.list_nodegroups(clusterName=cluster_name)
            node_groups = response.get('nodegroups', [])
            
            if not node_groups:
                return CheckResult(
                    check_id="EKS.3",
                    name="EKS Node Group Security",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="EKS cluster has no managed node groups",
                    evidence="No managed node groups found",
                    remediation="Review cluster worker node configuration",
                    resource_id=cluster_name
                )
            
            security_issues = []
            public_subnets = []
            
            for ng_name in node_groups:
                try:
                    ng_response = eks_client.describe_nodegroup(
                        clusterName=cluster_name,
                        nodegroupName=ng_name
                    )
                    
                    nodegroup = ng_response.get('nodegroup', {})
                    subnets = nodegroup.get('subnets', [])
                    
                    # Check if node group is in public subnets (basic check by name)
                    public_subnet_indicators = ['public', 'pub']
                    for subnet in subnets:
                        if any(indicator in subnet.lower() for indicator in public_subnet_indicators):
                            public_subnets.append(subnet)
                    
                    # Check remote access configuration
                    remote_access = nodegroup.get('remoteAccess', {})
                    if remote_access:
                        ec2_ssh_key = remote_access.get('ec2SshKey', '')
                        source_security_groups = remote_access.get('sourceSecurityGroups', [])
                        
                        if ec2_ssh_key and not source_security_groups:
                            security_issues.append(f"Node group {ng_name} has SSH access without security group restrictions")
                
                except ClientError:
                    continue
            
            if security_issues or public_subnets:
                issues = security_issues + [f"Potential public subnet: {subnet}" for subnet in public_subnets]
                return CheckResult(
                    check_id="EKS.3",
                    name="EKS Node Group Security",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="EKS node groups have potential security issues",
                    evidence=f"Issues found: {'; '.join(issues)}",
                    remediation="Review node group subnet placement and remote access configuration",
                    resource_id=cluster_name
                )
            else:
                return CheckResult(
                    check_id="EKS.3",
                    name="EKS Node Group Security",
                    status=CheckStatus.OK,
                    severity=config.severity,
                    description="EKS node groups appear to be securely configured",
                    evidence=f"Checked {len(node_groups)} node groups",
                    remediation=None,
                    resource_id=cluster_name
                )
        
        except Exception as e:
            return self.create_error_result("EKS.3", "EKS Node Group Security", 
                                          config.severity, cluster_name, e)
    
    def check_cluster_version(self, cluster_name: str, config: CheckConfig) -> CheckResult:
        """Check EKS cluster Kubernetes version."""
        try:
            eks_client = self.aws_client.get_client('eks', self.current_region)
            
            response = eks_client.describe_cluster(name=cluster_name)
            cluster = response.get('cluster', {})
            
            version = cluster.get('version', '')
            status = cluster.get('status', '')
            
            # Basic version check - in practice, you'd want to check against known supported versions
            if version:
                # Check if version looks recent (very basic check)
                try:
                    major, minor = version.split('.')[:2]
                    version_number = float(f"{major}.{minor}")
                    
                    if version_number >= 1.24:  # Arbitrary threshold for "recent"
                        return CheckResult(
                            check_id="EKS.4",
                            name="EKS Cluster Version",
                            status=CheckStatus.OK,
                            severity=config.severity,
                            description="EKS cluster is running a recent Kubernetes version",
                            evidence=f"Kubernetes version: {version}, status: {status}",
                            remediation=None,
                            resource_id=cluster_name
                        )
                    else:
                        return CheckResult(
                            check_id="EKS.4",
                            name="EKS Cluster Version",
                            status=CheckStatus.NEED_REVIEW,
                            severity=config.severity,
                            description="EKS cluster may be running an older Kubernetes version",
                            evidence=f"Kubernetes version: {version}, status: {status}",
                            remediation="Consider upgrading to a more recent Kubernetes version",
                            resource_id=cluster_name
                        )
                except ValueError:
                    return CheckResult(
                        check_id="EKS.4",
                        name="EKS Cluster Version",
                        status=CheckStatus.NEED_REVIEW,
                        severity=config.severity,
                        description="Unable to parse EKS cluster Kubernetes version",
                        evidence=f"Version: {version}, status: {status}",
                        remediation="Review cluster version and update strategy",
                        resource_id=cluster_name
                    )
            else:
                return CheckResult(
                    check_id="EKS.4",
                    name="EKS Cluster Version",
                    status=CheckStatus.ERROR,
                    severity=config.severity,
                    description="Unable to determine EKS cluster Kubernetes version",
                    evidence=f"Status: {status}",
                    remediation="Check cluster status and configuration",
                    resource_id=cluster_name
                )
        
        except Exception as e:
            return self.create_error_result("EKS.4", "EKS Cluster Version", 
                                          config.severity, cluster_name, e)
    
    def run_all_checks(self, cluster_names: List[str], config_checks: Dict[str, CheckConfig], region: str = None) -> List[CheckResult]:
        """Run all EKS security checks for given clusters.
        
        Args:
            cluster_names: List of EKS cluster names
            config_checks: Dictionary of check configurations
            region: AWS region being checked
            
        Returns:
            List of CheckResult objects
        """
        results = []
        
        for cluster_name in cluster_names:
            self.logger.info(f"Running EKS security checks for cluster: {cluster_name}")
            
            # Endpoint access check
            if 'endpoint_access' in config_checks:
                result = self.check_cluster_endpoint_access(cluster_name, config_checks['endpoint_access'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
            
            # Cluster logging check
            if 'cluster_logging' in config_checks:
                result = self.check_cluster_logging(cluster_name, config_checks['cluster_logging'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
            
            # Node group security check
            if 'node_group_security' in config_checks:
                result = self.check_node_group_security(cluster_name, config_checks['node_group_security'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
            
            # Cluster version check
            if 'cluster_version' in config_checks:
                result = self.check_cluster_version(cluster_name, config_checks['cluster_version'])
                if result:
                    result.region = region or self.current_region
                    results.append(result)
        
        return results