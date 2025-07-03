"""Command Line Interface for AWS Security Audit Tool."""

import click
import logging
import sys
import os
from pathlib import Path
from typing import List

from .input_validator import InputValidator
from .aws_client import AWSClientManager
from .config_manager import ConfigManager
from .security_engine import SecurityEngine
from .reports.report_generator import ReportGenerator


# Configure logging
def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Reduce boto3/urllib3 logging noise
    logging.getLogger('boto3').setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)


@click.command()
@click.option('--account-id', required=True, help='AWS Account ID (12-digit number)')
@click.option('--auth-method', default='profile', 
              type=click.Choice(['profile', 'role', 'keys', 'instance']),
              help='Authentication method')
@click.option('--profile-name', help='AWS CLI profile name (for profile auth)')
@click.option('--role-arn', help='IAM role ARN (for role auth)')
@click.option('--access-key-id', help='AWS access key ID (for keys auth)')
@click.option('--secret-access-key', help='AWS secret access key (for keys auth)')
@click.option('--security-profile', default='CIS_AWS_Foundations',
              type=click.Choice(['CIS_AWS_Foundations', 'NIST_Cybersecurity', 'PCI_DSS', 'SOC_2', 'custom']),
              help='Security profile to use')
@click.option('--config-file', help='Custom configuration file (for custom security profile)')
@click.option('--output-format', multiple=True, default=['markdown'],
              type=click.Choice(['json', 'csv', 'markdown']),
              help='Output format(s) - can specify multiple')
@click.option('--output-dir', default='./reports', help='Output directory for reports')
@click.option('--regions', help='Comma-separated list of AWS regions (default: current region)')
@click.option('--services', help='Comma-separated list of services to check (default: all)')
@click.option('--parallel-checks', default=5, type=int, help='Number of parallel check threads')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option('--dry-run', is_flag=True, help='Validate configuration without running checks')
def main(account_id, auth_method, profile_name, role_arn, access_key_id, secret_access_key,
         security_profile, config_file, output_format, output_dir, regions, services,
         parallel_checks, verbose, dry_run):
    """AWS Security Audit Tool - Comprehensive security assessment for AWS accounts."""
    
    # Setup logging
    setup_logging(verbose)
    logger = logging.getLogger(__name__)
    
    logger.info("Starting AWS Security Audit Tool")
    logger.info(f"Account ID: {account_id}")
    logger.info(f"Authentication: {auth_method}")
    logger.info(f"Security Profile: {security_profile}")
    
    try:
        # Validate input parameters
        validator = InputValidator()
        
        auth_params = {
            'profile_name': profile_name,
            'role_arn': role_arn,
            'access_key_id': access_key_id,
            'secret_access_key': secret_access_key
        }
        
        validation_params = {
            'account_id': account_id,
            'auth_method': auth_method,
            'security_profile': security_profile,
            'config_file': config_file,
            'output_formats': list(output_format),
            'output_dir': output_dir,
            'parallel_checks': parallel_checks,
            'regions': regions.split(',') if regions else None,
            **auth_params
        }
        
        validation_result = validator.validate_all(validation_params)
        
        if not validation_result.is_valid:
            logger.error("Input validation failed:")
            for error in validation_result.errors:
                logger.error(f"  - {error}")
            sys.exit(1)
        
        if validation_result.warnings:
            logger.warning("Input validation warnings:")
            for warning in validation_result.warnings:
                logger.warning(f"  - {warning}")
        
        if dry_run:
            logger.info("Dry run mode - configuration validation completed successfully")
            return
        
        # Parse regions and services
        target_regions = None
        if regions:
            target_regions = [r.strip() for r in regions.split(',')]
        
        target_services = None
        if services:
            target_services = [s.strip() for s in services.split(',')]
        
        # Load security profile
        config_manager = ConfigManager()
        profile = config_manager.get_profile(security_profile, config_file)
        
        logger.info(f"Loaded security profile: {profile.name}")
        logger.info(f"Profile version: {profile.version}")
        
        # Initialize AWS client
        aws_client = AWSClientManager(
            account_id=account_id,
            auth_method=auth_method,
            **auth_params
        )
        
        # Determine regions to check
        if target_regions:
            audit_regions = target_regions
        else:
            audit_regions = [aws_client.region]
        
        logger.info(f"Will audit regions: {', '.join(audit_regions)}")
        
        # Initialize security engine
        security_engine = SecurityEngine(
            aws_client=aws_client,
            security_profile=profile,
            regions=audit_regions,
            max_workers=parallel_checks
        )
        
        # Run security checks
        logger.info("Starting security checks...")
        
        if target_services:
            logger.info(f"Running checks for services: {', '.join(target_services)}")
            results = security_engine.run_specific_checks(target_services, parallel=parallel_checks > 1)
        else:
            logger.info("Running checks for all enabled services")
            results = security_engine.run_all_checks(parallel=parallel_checks > 1)
        
        if not results:
            logger.warning("No security check results found")
            return
        
        # Generate reports
        logger.info("Generating security audit reports...")
        
        report_generator = ReportGenerator(account_id, profile)
        saved_files = report_generator.save_reports(
            results=results,
            output_dir=output_dir,
            formats=list(output_format)
        )
        
        # Summary
        logger.info("Security audit completed successfully!")
        logger.info(f"Total checks performed: {len(results)}")
        
        # Count results by status
        from .checks.base_checks import CheckStatus
        status_counts = {}
        for result in results:
            status_counts[result.status] = status_counts.get(result.status, 0) + 1
        
        logger.info("Results summary:")
        logger.info(f"  - Passed (OK): {status_counts.get(CheckStatus.OK, 0)}")
        logger.info(f"  - Failed (NOK): {status_counts.get(CheckStatus.NOK, 0)}")
        logger.info(f"  - Needs Review: {status_counts.get(CheckStatus.NEED_REVIEW, 0)}")
        logger.info(f"  - Errors: {status_counts.get(CheckStatus.ERROR, 0)}")
        
        logger.info("Generated reports:")
        for format_type, filepath in saved_files.items():
            logger.info(f"  - {format_type.upper()}: {filepath}")
        
        # Calculate overall score for exit code
        total_checks = len(results)
        failed_checks = status_counts.get(CheckStatus.NOK, 0)
        
        if total_checks > 0:
            failure_rate = failed_checks / total_checks
            if failure_rate > 0.2:  # More than 20% failures
                logger.warning("High failure rate detected - review security findings")
                sys.exit(2)  # Warning exit code
        
    except KeyboardInterrupt:
        logger.info("Audit interrupted by user")
        sys.exit(130)
    
    except Exception as e:
        logger.error(f"Audit failed with error: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    
    finally:
        # Cleanup AWS client
        try:
            aws_client.close()
        except:
            pass


if __name__ == '__main__':
    main()