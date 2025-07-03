"""ElastiCache security checks for AWS Security Audit Tool."""

import logging
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError

from ..aws_client import AWSClientManager
from ..config_manager import CheckConfig, Severity
from .base_checks import BaseSecurityChecks, CheckResult, CheckStatus


class ElastiCacheSecurityChecks(BaseSecurityChecks):
    """ElastiCache security checks implementation."""
    
    def __init__(self, aws_client: AWSClientManager):
        super().__init__(aws_client)
    
    def check_encryption_in_transit(self, cluster: Dict[str, Any], config: CheckConfig) -> CheckResult:
        """Check if ElastiCache cluster has encryption in transit enabled."""
        try:
            cluster_id = cluster.get('CacheClusterId', '')
            engine = cluster.get('Engine', '')
            
            # Encryption in transit availability depends on engine
            if engine == 'redis':
                transit_encryption_enabled = cluster.get('TransitEncryptionEnabled', False)
                
                require_tls = config.parameters.get('require_tls', True)
                
                if transit_encryption_enabled:
                    return CheckResult(
                        check_id="EC.1",
                        name="ElastiCache Encryption in Transit",
                        status=CheckStatus.OK,
                        severity=config.severity,
                        description="ElastiCache Redis cluster has encryption in transit enabled",
                        evidence="TransitEncryptionEnabled=True",
                        remediation=None,
                        resource_id=cluster_id
                    )
                else:
                    status = CheckStatus.NOK if require_tls else CheckStatus.NEED_REVIEW
                    return CheckResult(
                        check_id="EC.1",
                        name="ElastiCache Encryption in Transit",
                        status=status,
                        severity=config.severity,
                        description="ElastiCache Redis cluster does not have encryption in transit enabled",
                        evidence="TransitEncryptionEnabled=False",
                        remediation="Enable encryption in transit for Redis cluster",
                        resource_id=cluster_id
                    )
            elif engine == 'memcached':
                return CheckResult(
                    check_id="EC.1",
                    name="ElastiCache Encryption in Transit",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="ElastiCache Memcached does not support encryption in transit",
                    evidence="Engine: memcached",
                    remediation="Consider using Redis for encryption support",
                    resource_id=cluster_id
                )
            else:
                return CheckResult(
                    check_id="EC.1",
                    name="ElastiCache Encryption in Transit",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="Unknown ElastiCache engine type",
                    evidence=f"Engine: {engine}",
                    remediation="Review cluster engine configuration",
                    resource_id=cluster_id
                )
        
        except Exception as e:
            return self.create_error_result("EC.1", "ElastiCache Encryption in Transit", 
                                          config.severity, cluster_id, e)
    
    def check_encryption_at_rest(self, cluster: Dict[str, Any], config: CheckConfig) -> CheckResult:
        """Check if ElastiCache cluster has encryption at rest enabled."""
        try:
            cluster_id = cluster.get('CacheClusterId', '')
            engine = cluster.get('Engine', '')
            
            if engine == 'redis':
                at_rest_encryption_enabled = cluster.get('AtRestEncryptionEnabled', False)
                
                if at_rest_encryption_enabled:
                    return CheckResult(
                        check_id="EC.2",
                        name="ElastiCache Encryption at Rest",
                        status=CheckStatus.OK,
                        severity=config.severity,
                        description="ElastiCache Redis cluster has encryption at rest enabled",
                        evidence="AtRestEncryptionEnabled=True",
                        remediation=None,
                        resource_id=cluster_id
                    )
                else:
                    return CheckResult(
                        check_id="EC.2",
                        name="ElastiCache Encryption at Rest",
                        status=CheckStatus.NEED_REVIEW,
                        severity=config.severity,
                        description="ElastiCache Redis cluster does not have encryption at rest enabled",
                        evidence="AtRestEncryptionEnabled=False",
                        remediation="Enable encryption at rest for Redis cluster",
                        resource_id=cluster_id
                    )
            elif engine == 'memcached':
                return CheckResult(
                    check_id="EC.2",
                    name="ElastiCache Encryption at Rest",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="ElastiCache Memcached does not support encryption at rest",
                    evidence="Engine: memcached",
                    remediation="Consider using Redis for encryption support",
                    resource_id=cluster_id
                )
            else:
                return CheckResult(
                    check_id="EC.2",
                    name="ElastiCache Encryption at Rest",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="Unknown ElastiCache engine type",
                    evidence=f"Engine: {engine}",
                    remediation="Review cluster engine configuration",
                    resource_id=cluster_id
                )
        
        except Exception as e:
            return self.create_error_result("EC.2", "ElastiCache Encryption at Rest", 
                                          config.severity, cluster_id, e)
    
    def check_subnet_groups(self, cluster: Dict[str, Any], config: CheckConfig) -> CheckResult:
        """Check ElastiCache cluster subnet group configuration."""
        try:
            cluster_id = cluster.get('CacheClusterId', '')
            subnet_group_name = cluster.get('CacheSubnetGroupName', '')
            
            if not subnet_group_name:
                return CheckResult(
                    check_id="EC.3",
                    name="ElastiCache Subnet Groups",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="ElastiCache cluster has no subnet group configured",
                    evidence="No CacheSubnetGroupName found",
                    remediation="Configure appropriate subnet group for network isolation",
                    resource_id=cluster_id
                )
            
            # Get subnet group details
            elasticache_client = self.aws_client.get_client('elasticache')
            
            try:
                response = elasticache_client.describe_cache_subnet_groups(
                    CacheSubnetGroupName=subnet_group_name
                )
                
                subnet_groups = response.get('CacheSubnetGroups', [])
                
                if subnet_groups:
                    subnet_group = subnet_groups[0]
                    vpc_id = subnet_group.get('VpcId', '')
                    subnets = subnet_group.get('Subnets', [])
                    
                    # Basic check for subnet configuration
                    subnet_azs = [subnet.get('SubnetAvailabilityZone', {}).get('Name', '') for subnet in subnets]
                    
                    return CheckResult(
                        check_id="EC.3",
                        name="ElastiCache Subnet Groups",
                        status=CheckStatus.OK,
                        severity=config.severity,
                        description="ElastiCache cluster has subnet group configured",
                        evidence=f"Subnet group: {subnet_group_name}, VPC: {vpc_id}, AZs: {', '.join(subnet_azs)}",
                        remediation=None,
                        resource_id=cluster_id
                    )
                else:
                    return CheckResult(
                        check_id="EC.3",
                        name="ElastiCache Subnet Groups",
                        status=CheckStatus.ERROR,
                        severity=config.severity,
                        description="ElastiCache subnet group not found",
                        evidence=f"Subnet group {subnet_group_name} not found",
                        remediation="Check subnet group configuration",
                        resource_id=cluster_id
                    )
            
            except ClientError as e:
                if e.response['Error']['Code'] == 'CacheSubnetGroupNotFoundFault':
                    return CheckResult(
                        check_id="EC.3",
                        name="ElastiCache Subnet Groups",
                        status=CheckStatus.ERROR,
                        severity=config.severity,
                        description="ElastiCache subnet group does not exist",
                        evidence=f"Subnet group {subnet_group_name} not found",
                        remediation="Create or configure appropriate subnet group",
                        resource_id=cluster_id
                    )
                else:
                    raise
        
        except Exception as e:
            return self.create_error_result("EC.3", "ElastiCache Subnet Groups", 
                                          config.severity, cluster_id, e)
    
    def check_auth_token(self, cluster: Dict[str, Any], config: CheckConfig) -> CheckResult:
        """Check ElastiCache cluster authentication configuration."""
        try:
            cluster_id = cluster.get('CacheClusterId', '')
            engine = cluster.get('Engine', '')
            
            if engine == 'redis':
                auth_token_enabled = cluster.get('AuthTokenEnabled', False)
                
                if auth_token_enabled:
                    return CheckResult(
                        check_id="EC.4",
                        name="ElastiCache Authentication",
                        status=CheckStatus.OK,
                        severity=config.severity,
                        description="ElastiCache Redis cluster has authentication enabled",
                        evidence="AuthTokenEnabled=True",
                        remediation=None,
                        resource_id=cluster_id
                    )
                else:
                    return CheckResult(
                        check_id="EC.4",
                        name="ElastiCache Authentication",
                        status=CheckStatus.NEED_REVIEW,
                        severity=config.severity,
                        description="ElastiCache Redis cluster does not have authentication enabled",
                        evidence="AuthTokenEnabled=False",
                        remediation="Enable Redis AUTH for better security",
                        resource_id=cluster_id
                    )
            elif engine == 'memcached':
                return CheckResult(
                    check_id="EC.4",
                    name="ElastiCache Authentication",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="ElastiCache Memcached has limited authentication options",
                    evidence="Engine: memcached",
                    remediation="Consider using Redis for better authentication support",
                    resource_id=cluster_id
                )
            else:
                return CheckResult(
                    check_id="EC.4",
                    name="ElastiCache Authentication",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="Unknown ElastiCache engine type",
                    evidence=f"Engine: {engine}",
                    remediation="Review cluster engine configuration",
                    resource_id=cluster_id
                )
        
        except Exception as e:
            return self.create_error_result("EC.4", "ElastiCache Authentication", 
                                          config.severity, cluster_id, e)
    
    def check_backup_configuration(self, cluster: Dict[str, Any], config: CheckConfig) -> CheckResult:
        """Check ElastiCache cluster backup configuration."""
        try:
            cluster_id = cluster.get('CacheClusterId', '')
            engine = cluster.get('Engine', '')
            
            if engine == 'redis':
                # For Redis, check if it's part of a replication group with backup enabled
                replication_group_id = cluster.get('ReplicationGroupId', '')
                
                if replication_group_id:
                    # This is part of a replication group, check replication group backup settings
                    elasticache_client = self.aws_client.get_client('elasticache')
                    
                    try:
                        response = elasticache_client.describe_replication_groups(
                            ReplicationGroupId=replication_group_id
                        )
                        
                        replication_groups = response.get('ReplicationGroups', [])
                        
                        if replication_groups:
                            rg = replication_groups[0]
                            snapshot_retention_limit = rg.get('SnapshotRetentionLimit', 0)
                            snapshot_window = rg.get('SnapshotWindow', '')
                            
                            if snapshot_retention_limit > 0:
                                return CheckResult(
                                    check_id="EC.5",
                                    name="ElastiCache Backup Configuration",
                                    status=CheckStatus.OK,
                                    severity=config.severity,
                                    description="ElastiCache Redis has automated backups enabled",
                                    evidence=f"Snapshot retention: {snapshot_retention_limit} days, window: {snapshot_window}",
                                    remediation=None,
                                    resource_id=cluster_id
                                )
                            else:
                                return CheckResult(
                                    check_id="EC.5",
                                    name="ElastiCache Backup Configuration",
                                    status=CheckStatus.NEED_REVIEW,
                                    severity=config.severity,
                                    description="ElastiCache Redis does not have automated backups enabled",
                                    evidence=f"Snapshot retention: {snapshot_retention_limit} days",
                                    remediation="Enable automated backups for data protection",
                                    resource_id=cluster_id
                                )
                        else:
                            return CheckResult(
                                check_id="EC.5",
                                name="ElastiCache Backup Configuration",
                                status=CheckStatus.ERROR,
                                severity=config.severity,
                                description="ElastiCache replication group not found",
                                evidence=f"Replication group {replication_group_id} not found",
                                remediation="Check replication group configuration",
                                resource_id=cluster_id
                            )
                    
                    except ClientError:
                        return CheckResult(
                            check_id="EC.5",
                            name="ElastiCache Backup Configuration",
                            status=CheckStatus.ERROR,
                            severity=config.severity,
                            description="Unable to check ElastiCache backup configuration",
                            evidence="Error accessing replication group details",
                            remediation="Check permissions and configuration",
                            resource_id=cluster_id
                        )
                else:
                    return CheckResult(
                        check_id="EC.5",
                        name="ElastiCache Backup Configuration",
                        status=CheckStatus.NEED_REVIEW,
                        severity=config.severity,
                        description="ElastiCache Redis cluster is not part of a replication group",
                        evidence="No replication group configured",
                        remediation="Consider using replication groups for backup capabilities",
                        resource_id=cluster_id
                    )
            elif engine == 'memcached':
                return CheckResult(
                    check_id="EC.5",
                    name="ElastiCache Backup Configuration",
                    status=CheckStatus.OK,
                    severity=config.severity,
                    description="ElastiCache Memcached does not support backups",
                    evidence="Engine: memcached (no backup capability)",
                    remediation=None,
                    resource_id=cluster_id
                )
            else:
                return CheckResult(
                    check_id="EC.5",
                    name="ElastiCache Backup Configuration",
                    status=CheckStatus.NEED_REVIEW,
                    severity=config.severity,
                    description="Unknown ElastiCache engine type",
                    evidence=f"Engine: {engine}",
                    remediation="Review cluster engine configuration",
                    resource_id=cluster_id
                )
        
        except Exception as e:
            return self.create_error_result("EC.5", "ElastiCache Backup Configuration", 
                                          config.severity, cluster_id, e)
    
    def run_all_checks(self, clusters: List[Dict[str, Any]], config_checks: Dict[str, CheckConfig]) -> List[CheckResult]:
        """Run all ElastiCache security checks for given clusters.
        
        Args:
            clusters: List of ElastiCache cluster dictionaries
            config_checks: Dictionary of check configurations
            
        Returns:
            List of CheckResult objects
        """
        results = []
        
        for cluster in clusters:
            cluster_id = cluster.get('CacheClusterId', 'unknown')
            self.logger.info(f"Running ElastiCache security checks for cluster: {cluster_id}")
            
            # Encryption in transit check
            if 'encryption_in_transit' in config_checks:
                result = self.check_encryption_in_transit(cluster, config_checks['encryption_in_transit'])
                results.append(result)
            
            # Encryption at rest check
            if 'encryption_at_rest' in config_checks:
                result = self.check_encryption_at_rest(cluster, config_checks['encryption_at_rest'])
                results.append(result)
            
            # Subnet groups check
            if 'subnet_groups' in config_checks:
                result = self.check_subnet_groups(cluster, config_checks['subnet_groups'])
                results.append(result)
            
            # Authentication check
            if 'auth_token' in config_checks:
                result = self.check_auth_token(cluster, config_checks['auth_token'])
                results.append(result)
            
            # Backup configuration check
            if 'backup_configuration' in config_checks:
                result = self.check_backup_configuration(cluster, config_checks['backup_configuration'])
                results.append(result)
        
        return results