"""AWS Client Manager for Security Audit Tool."""

import boto3
import time
import logging
from typing import Dict, Optional, Any, List
from botocore.exceptions import ClientError, NoCredentialsError, TokenRetrievalError
from botocore.config import Config
from dataclasses import dataclass
from enum import Enum

from .input_validator import AuthMethod


class ClientType(Enum):
    """Supported AWS service clients."""
    S3 = "s3"
    EC2 = "ec2"
    EKS = "eks"
    ELASTICACHE = "elasticache"
    RDS = "rds"
    DYNAMODB = "dynamodb"
    KMS = "kms"
    ELB = "elb"
    ELBV2 = "elbv2"
    IAM = "iam"
    STS = "sts"


@dataclass
class RetryConfig:
    """Configuration for API retry logic."""
    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0


class AWSClientManager:
    """Manages AWS service clients with authentication and error handling."""
    
    def __init__(self, account_id: str, auth_method: str, 
                 region: str = "us-east-1", ca_bundle: Optional[str] = None, 
                 verify_ssl: bool = True, **auth_params):
        """Initialize AWS client manager.
        
        Args:
            account_id: Target AWS account ID
            auth_method: Authentication method (profile/role/keys/instance)
            region: AWS region for API calls
            ca_bundle: Path to custom CA bundle file (PEM format)
            verify_ssl: Enable/disable SSL verification
            **auth_params: Authentication-specific parameters
        """
        self.account_id = account_id
        self.auth_method = AuthMethod(auth_method.lower())
        self.region = region
        self.auth_params = auth_params
        self.ca_bundle = ca_bundle
        self.verify_ssl = verify_ssl
        self.session = None
        self.clients = {}
        self.retry_config = RetryConfig()
        
        # Configure logging
        self.logger = logging.getLogger(__name__)
        
        # Configure boto3 client settings
        self.boto_config = self._create_boto_config(region)
        
        # Log SSL configuration
        if not self.verify_ssl:
            self.logger.warning("SSL verification is disabled - this is not recommended for production")
        elif self.ca_bundle:
            self.logger.info(f"Using custom CA bundle: {self.ca_bundle}")
        else:
            self.logger.info("Using system default CA bundle for SSL verification")
        
        # Initialize session
        self._create_session()
    
    def _create_boto_config(self, region: str) -> Config:
        """Create boto3 configuration.
        
        Args:
            region: AWS region for the configuration
            
        Returns:
            Boto3 Config object
        """
        config_params = {
            'retries': {
                'max_attempts': self.retry_config.max_attempts,
                'mode': 'adaptive'
            },
            'max_pool_connections': 50,
            'region_name': region
        }
        
        return Config(**config_params)
    
    def _get_ssl_params(self) -> dict:
        """Get SSL parameters for client creation.
        
        Returns:
            Dictionary with SSL parameters for boto3 client
        """
        import os
        
        ssl_params = {}
        
        # Configure SSL verification
        if not self.verify_ssl:
            # Disable SSL verification entirely
            ssl_params['verify'] = False
        elif self.ca_bundle:
            # Use custom CA bundle
            if os.path.exists(self.ca_bundle):
                ssl_params['verify'] = self.ca_bundle
            else:
                self.logger.error(f"CA bundle file not found: {self.ca_bundle}")
                raise FileNotFoundError(f"CA bundle file not found: {self.ca_bundle}")
        else:
            # Use system default CA bundle (default behavior)
            ssl_params['verify'] = True
        
        return ssl_params
    
    def _create_session(self) -> None:
        """Create boto3 session based on authentication method."""
        try:
            if self.auth_method == AuthMethod.PROFILE:
                profile_name = self.auth_params.get('profile_name', 'default')
                self.session = boto3.Session(profile_name=profile_name)
                self.logger.info(f"Created session with profile: {profile_name}")
            
            elif self.auth_method == AuthMethod.ROLE:
                role_arn = self.auth_params.get('role_arn')
                session_name = f"aws-security-audit-{int(time.time())}"
                
                # Create temporary session to assume role
                temp_session = boto3.Session()
                ssl_params = self._get_ssl_params()
                sts_client = temp_session.client('sts', config=self.boto_config, **ssl_params)
                
                response = sts_client.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName=session_name,
                    DurationSeconds=3600
                )
                
                credentials = response['Credentials']
                self.session = boto3.Session(
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken']
                )
                self.logger.info(f"Assumed role: {role_arn}")
            
            elif self.auth_method == AuthMethod.KEYS:
                self.session = boto3.Session(
                    aws_access_key_id=self.auth_params.get('access_key_id'),
                    aws_secret_access_key=self.auth_params.get('secret_access_key')
                )
                self.logger.info("Created session with access keys")
            
            elif self.auth_method == AuthMethod.INSTANCE:
                self.session = boto3.Session()
                self.logger.info("Using instance profile for authentication")
            
            # Validate session by calling STS get-caller-identity
            self._validate_session()
            
        except Exception as e:
            self.logger.error(f"Failed to create AWS session: {e}")
            raise
    
    def _validate_session(self) -> None:
        """Validate AWS session by calling STS get-caller-identity."""
        try:
            ssl_params = self._get_ssl_params()
            sts_client = self.session.client('sts', config=self.boto_config, **ssl_params)
            identity = sts_client.get_caller_identity()
            
            session_account_id = identity.get('Account')
            if session_account_id != self.account_id:
                self.logger.warning(
                    f"Session account ID ({session_account_id}) differs from "
                    f"target account ID ({self.account_id})"
                )
            
            self.logger.info(
                f"Session validated. User: {identity.get('Arn')}, "
                f"Account: {session_account_id}"
            )
            
        except Exception as e:
            self.logger.error(f"Session validation failed: {e}")
            raise
    
    def get_client(self, service: str, region: Optional[str] = None) -> Any:
        """Get AWS service client with caching and error handling.
        
        Args:
            service: AWS service name (e.g., 's3', 'ec2', 'rds')
            region: Optional region override
            
        Returns:
            Boto3 client for the specified service
        """
        client_key = f"{service}_{region or self.region}"
        
        if client_key not in self.clients:
            try:
                # Get SSL parameters for client creation
                ssl_params = self._get_ssl_params()
                
                self.clients[client_key] = self.session.client(
                    service,
                    region_name=region or self.region,
                    config=self.boto_config,
                    **ssl_params
                )
                self.logger.debug(f"Created {service} client for {region or self.region}")
            except Exception as e:
                self.logger.error(f"Failed to create {service} client: {e}")
                raise
        
        return self.clients[client_key]
    
    def get_available_regions(self, service: str) -> List[str]:
        """Get list of available regions for a service.
        
        Args:
            service: AWS service name
            
        Returns:
            List of available regions
        """
        try:
            session = boto3.Session()
            return session.get_available_regions(service)
        except Exception as e:
            self.logger.error(f"Failed to get regions for {service}: {e}")
            return [self.region]
    
    def execute_with_retry(self, func, *args, **kwargs) -> Any:
        """Execute function with exponential backoff retry.
        
        Args:
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Function result
        """
        last_exception = None
        
        for attempt in range(self.retry_config.max_attempts):
            try:
                return func(*args, **kwargs)
            
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')
                
                # Don't retry on certain errors
                if error_code in ['AccessDenied', 'InvalidUserID.NotFound', 
                                'UnauthorizedOperation', 'Forbidden']:
                    self.logger.error(f"Non-retryable error: {e}")
                    raise
                
                # Retry on throttling and temporary errors
                if error_code in ['Throttling', 'ThrottlingException', 
                                'RequestLimitExceeded', 'ServiceUnavailable']:
                    last_exception = e
                    delay = min(
                        self.retry_config.base_delay * 
                        (self.retry_config.exponential_base ** attempt),
                        self.retry_config.max_delay
                    )
                    
                    self.logger.warning(
                        f"Retrying after {delay}s due to {error_code} "
                        f"(attempt {attempt + 1}/{self.retry_config.max_attempts})"
                    )
                    time.sleep(delay)
                    continue
                
                # Don't retry on other client errors
                self.logger.error(f"Client error: {e}")
                raise
            
            except Exception as e:
                # Retry on network and temporary errors
                last_exception = e
                delay = min(
                    self.retry_config.base_delay * 
                    (self.retry_config.exponential_base ** attempt),
                    self.retry_config.max_delay
                )
                
                self.logger.warning(
                    f"Retrying after {delay}s due to {type(e).__name__}: {e} "
                    f"(attempt {attempt + 1}/{self.retry_config.max_attempts})"
                )
                time.sleep(delay)
        
        # All retries exhausted
        self.logger.error(f"All retry attempts exhausted. Last error: {last_exception}")
        raise last_exception
    
    def list_s3_buckets(self) -> List[Dict[str, Any]]:
        """List all S3 buckets with error handling."""
        s3_client = self.get_client('s3')
        
        def _list_buckets():
            response = s3_client.list_buckets()
            return response.get('Buckets', [])
        
        return self.execute_with_retry(_list_buckets)
    
    def list_ec2_instances(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all EC2 instances in a region."""
        ec2_client = self.get_client('ec2', region)
        
        def _list_instances():
            response = ec2_client.describe_instances()
            instances = []
            for reservation in response.get('Reservations', []):
                instances.extend(reservation.get('Instances', []))
            return instances
        
        return self.execute_with_retry(_list_instances)
    
    def list_rds_instances(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all RDS instances in a region."""
        rds_client = self.get_client('rds', region)
        
        def _list_instances():
            response = rds_client.describe_db_instances()
            return response.get('DBInstances', [])
        
        return self.execute_with_retry(_list_instances)
    
    def list_rds_clusters(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all RDS clusters in a region."""
        rds_client = self.get_client('rds', region)
        
        def _list_clusters():
            response = rds_client.describe_db_clusters()
            return response.get('DBClusters', [])
        
        return self.execute_with_retry(_list_clusters)
    
    def list_eks_clusters(self, region: Optional[str] = None) -> List[str]:
        """List all EKS clusters in a region."""
        eks_client = self.get_client('eks', region)
        
        def _list_clusters():
            response = eks_client.list_clusters()
            return response.get('clusters', [])
        
        return self.execute_with_retry(_list_clusters)
    
    def list_dynamodb_tables(self, region: Optional[str] = None) -> List[str]:
        """List all DynamoDB tables in a region."""
        dynamodb_client = self.get_client('dynamodb', region)
        
        def _list_tables():
            response = dynamodb_client.list_tables()
            return response.get('TableNames', [])
        
        return self.execute_with_retry(_list_tables)
    
    def list_elasticache_clusters(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all ElastiCache clusters in a region."""
        elasticache_client = self.get_client('elasticache', region)
        
        def _list_clusters():
            response = elasticache_client.describe_cache_clusters()
            return response.get('CacheClusters', [])
        
        return self.execute_with_retry(_list_clusters)
    
    def list_load_balancers(self, region: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
        """List all load balancers (ALB/NLB and Classic) in a region."""
        elbv2_client = self.get_client('elbv2', region)
        elb_client = self.get_client('elb', region)
        
        def _list_elbv2():
            response = elbv2_client.describe_load_balancers()
            return response.get('LoadBalancers', [])
        
        def _list_elb():
            response = elb_client.describe_load_balancers()
            return response.get('LoadBalancerDescriptions', [])
        
        return {
            'elbv2': self.execute_with_retry(_list_elbv2),
            'elb': self.execute_with_retry(_list_elb)
        }
    
    def list_kms_keys(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all KMS keys in a region."""
        kms_client = self.get_client('kms', region)
        
        def _list_keys():
            response = kms_client.list_keys()
            return response.get('Keys', [])
        
        return self.execute_with_retry(_list_keys)
    
    def close(self) -> None:
        """Clean up resources."""
        self.clients.clear()
        self.session = None
        self.logger.info("AWS client manager closed")