"""Security Checks Engine for AWS Security Audit Tool."""

import logging
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

from .aws_client import AWSClientManager
from .config_manager import SecurityProfile, ConfigManager
from .checks.base_checks import CheckResult
from .checks.s3_checks import S3SecurityChecks
from .checks.ec2_checks import EC2SecurityChecks
from .checks.security_groups_checks import SecurityGroupsChecks
from .checks.vpc_checks import VPCSecurityChecks
from .checks.rds_checks import RDSSecurityChecks
from .checks.dynamodb_checks import DynamoDBSecurityChecks
from .checks.eks_checks import EKSSecurityChecks
from .checks.elasticache_checks import ElastiCacheSecurityChecks
from .checks.kms_checks import KMSSecurityChecks
from .checks.load_balancer_checks import LoadBalancerSecurityChecks


class SecurityEngine:
    """Main engine for running AWS security checks."""
    
    def __init__(self, aws_client: AWSClientManager, security_profile: SecurityProfile, 
                 regions: Optional[List[str]] = None, max_workers: int = 5):
        self.aws_client = aws_client
        self.security_profile = security_profile
        self.regions = regions or [aws_client.region]
        self.max_workers = max_workers
        self.logger = logging.getLogger(__name__)
        
        # Initialize check classes
        self.check_classes = {
            's3': S3SecurityChecks(aws_client),
            'ec2': EC2SecurityChecks(aws_client),
            'security_groups': SecurityGroupsChecks(aws_client),
            'vpc': VPCSecurityChecks(aws_client),
            'rds': RDSSecurityChecks(aws_client),
            'dynamodb': DynamoDBSecurityChecks(aws_client),
            'eks': EKSSecurityChecks(aws_client),
            'elasticache': ElastiCacheSecurityChecks(aws_client),
            'kms': KMSSecurityChecks(aws_client),
            'load_balancer': LoadBalancerSecurityChecks(aws_client)
        }
    
    def discover_resources(self, region: str = None) -> Dict[str, List[Any]]:
        """Discover AWS resources across services."""
        target_region = region or self.aws_client.region
        self.logger.info(f"Discovering resources in region: {target_region}")
        
        resources = {}
        
        try:
            # S3 buckets (global resource)
            if region is None or region == 'us-east-1':  # Only check once
                resources['s3_buckets'] = self.aws_client.list_s3_buckets()
                self.logger.info(f"Found {len(resources['s3_buckets'])} S3 buckets")
            
            # EC2 instances
            resources['ec2_instances'] = self.aws_client.list_ec2_instances(target_region)
            self.logger.info(f"Found {len(resources['ec2_instances'])} EC2 instances in {target_region}")
            
            # Security Groups
            ec2_client = self.aws_client.get_client('ec2', target_region)
            sg_response = ec2_client.describe_security_groups()
            resources['security_groups'] = sg_response.get('SecurityGroups', [])
            self.logger.info(f"Found {len(resources['security_groups'])} security groups in {target_region}")
            
            # VPCs
            vpc_response = ec2_client.describe_vpcs()
            resources['vpcs'] = vpc_response.get('Vpcs', [])
            self.logger.info(f"Found {len(resources['vpcs'])} VPCs in {target_region}")
            
            # RDS instances
            resources['rds_instances'] = self.aws_client.list_rds_instances(target_region)
            self.logger.info(f"Found {len(resources['rds_instances'])} RDS instances in {target_region}")
            
            # RDS clusters
            resources['rds_clusters'] = self.aws_client.list_rds_clusters(target_region)
            self.logger.info(f"Found {len(resources['rds_clusters'])} RDS clusters in {target_region}")
            
            # DynamoDB tables
            resources['dynamodb_tables'] = self.aws_client.list_dynamodb_tables(target_region)
            self.logger.info(f"Found {len(resources['dynamodb_tables'])} DynamoDB tables in {target_region}")
            
            # EKS clusters
            resources['eks_clusters'] = self.aws_client.list_eks_clusters(target_region)
            self.logger.info(f"Found {len(resources['eks_clusters'])} EKS clusters in {target_region}")
            
            # ElastiCache clusters
            resources['elasticache_clusters'] = self.aws_client.list_elasticache_clusters(target_region)
            self.logger.info(f"Found {len(resources['elasticache_clusters'])} ElastiCache clusters in {target_region}")
            
            # KMS keys
            resources['kms_keys'] = self.aws_client.list_kms_keys(target_region)
            self.logger.info(f"Found {len(resources['kms_keys'])} KMS keys in {target_region}")
            
            # Load balancers
            resources['load_balancers'] = self.aws_client.list_load_balancers(target_region)
            total_lbs = len(resources['load_balancers'].get('elbv2', [])) + len(resources['load_balancers'].get('elb', []))
            self.logger.info(f"Found {total_lbs} load balancers in {target_region}")
            
        except Exception as e:
            self.logger.error(f"Error discovering resources in {target_region}: {e}")
            raise
        
        return resources
    
    def run_service_checks(self, service: str, resources: Dict[str, List[Any]], 
                          region: str = None) -> List[CheckResult]:
        """Run security checks for a specific service."""
        if service not in self.security_profile.categories:
            return []
        
        category_config = self.security_profile.categories[service]
        if not category_config.enabled:
            self.logger.info(f"Skipping {service} checks (disabled in profile)")
            return []
        
        check_class = self.check_classes.get(service)
        if not check_class:
            self.logger.warning(f"No check class found for service: {service}")
            return []
        
        self.logger.info(f"Running {service} security checks")
        start_time = time.time()
        
        try:
            # Map service to resource key
            resource_mapping = {
                's3': 's3_buckets',
                'ec2': 'ec2_instances',
                'security_groups': 'security_groups',
                'vpc': 'vpcs',
                'rds': 'rds_instances',  # Also handle clusters separately
                'dynamodb': 'dynamodb_tables',
                'eks': 'eks_clusters',
                'elasticache': 'elasticache_clusters',
                'kms': 'kms_keys',
                'load_balancer': 'load_balancers'
            }
            
            resource_key = resource_mapping.get(service)
            if not resource_key or resource_key not in resources:
                self.logger.warning(f"No resources found for {service}")
                return []
            
            service_resources = resources[resource_key]
            
            # Special handling for RDS (both instances and clusters)
            if service == 'rds':
                all_rds_resources = service_resources + resources.get('rds_clusters', [])
                results = check_class.run_all_checks(all_rds_resources, category_config.checks)
            else:
                results = check_class.run_all_checks(service_resources, category_config.checks)
            
            elapsed_time = time.time() - start_time
            self.logger.info(f"Completed {service} checks in {elapsed_time:.2f} seconds. Found {len(results)} results")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error running {service} checks: {e}")
            return []
    
    def run_all_checks(self, parallel: bool = True) -> List[CheckResult]:
        """Run all security checks across all enabled services and regions."""
        all_results = []
        
        for region in self.regions:
            self.logger.info(f"Starting security audit for region: {region}")
            
            # Discover resources
            try:
                resources = self.discover_resources(region)
            except Exception as e:
                self.logger.error(f"Failed to discover resources in {region}: {e}")
                continue
            
            # Run checks for each service
            if parallel and self.max_workers > 1:
                # Run service checks in parallel
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    future_to_service = {}
                    
                    for service in self.security_profile.categories.keys():
                        if service in self.check_classes:
                            future = executor.submit(self.run_service_checks, service, resources, region)
                            future_to_service[future] = service
                    
                    for future in as_completed(future_to_service):
                        service = future_to_service[future]
                        try:
                            results = future.result()
                            all_results.extend(results)
                        except Exception as e:
                            self.logger.error(f"Error in parallel execution for {service}: {e}")
            else:
                # Run service checks sequentially
                for service in self.security_profile.categories.keys():
                    if service in self.check_classes:
                        results = self.run_service_checks(service, resources, region)
                        all_results.extend(results)
        
        self.logger.info(f"Security audit completed. Total findings: {len(all_results)}")
        return all_results
    
    def run_specific_checks(self, services: List[str], parallel: bool = True) -> List[CheckResult]:
        """Run checks for specific services only."""
        all_results = []
        
        # Filter services to only those requested and available
        target_services = [s for s in services if s in self.security_profile.categories and s in self.check_classes]
        
        if not target_services:
            self.logger.warning("No valid services specified for checking")
            return []
        
        for region in self.regions:
            self.logger.info(f"Running checks for services {target_services} in region: {region}")
            
            # Discover resources
            try:
                resources = self.discover_resources(region)
            except Exception as e:
                self.logger.error(f"Failed to discover resources in {region}: {e}")
                continue
            
            # Run checks for specified services
            if parallel and self.max_workers > 1:
                with ThreadPoolExecutor(max_workers=min(self.max_workers, len(target_services))) as executor:
                    future_to_service = {}
                    
                    for service in target_services:
                        future = executor.submit(self.run_service_checks, service, resources, region)
                        future_to_service[future] = service
                    
                    for future in as_completed(future_to_service):
                        service = future_to_service[future]
                        try:
                            results = future.result()
                            all_results.extend(results)
                        except Exception as e:
                            self.logger.error(f"Error running {service} checks: {e}")
            else:
                for service in target_services:
                    results = self.run_service_checks(service, resources, region)
                    all_results.extend(results)
        
        return all_results