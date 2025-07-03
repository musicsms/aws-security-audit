# AWS Security Audit Tool

A comprehensive security audit tool for AWS accounts that generates detailed compliance reports with exportable formats for auditor review.

## Features

- **Comprehensive Coverage**: Audits 10 major AWS services (S3, EC2, RDS, VPC, EKS, ElastiCache, DynamoDB, KMS, Security Groups, Load Balancers)
- **Multiple Security Profiles**: Built-in support for CIS AWS Foundations, NIST Cybersecurity Framework, PCI DSS, SOC 2, and custom profiles
- **Multiple Authentication Methods**: Supports AWS CLI profiles, IAM roles, access keys, and EC2 instance profiles
- **Flexible Reporting**: Generates reports in Markdown, JSON, and CSV formats
- **Parallel Execution**: Optimized performance with configurable parallel checking
- **Detailed Evidence**: Each finding includes evidence and remediation guidance
- **Three-State Classification**: OK/NOK/NEED_REVIEW status system

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd security-compliance
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Install the package:
```bash
pip install -e .
```

## Quick Start

### Basic Usage

```bash
# Audit with default settings (CIS profile, current region)
aws-security-audit --account-id 123456789012

# Audit specific regions
aws-security-audit --account-id 123456789012 --regions us-east-1,us-west-2

# Use specific security profile
aws-security-audit --account-id 123456789012 --security-profile NIST_Cybersecurity

# Generate multiple report formats
aws-security-audit --account-id 123456789012 --output-format json --output-format csv --output-format markdown
```

### Authentication Options

```bash
# Use named AWS CLI profile
aws-security-audit --account-id 123456789012 --auth-method profile --profile-name production

# Use IAM role assumption
aws-security-audit --account-id 123456789012 --auth-method role --role-arn arn:aws:iam::123456789012:role/SecurityAuditRole

# Use access keys (not recommended for production)
aws-security-audit --account-id 123456789012 --auth-method keys --access-key-id AKIA... --secret-access-key ...

# Use EC2 instance profile (when running on EC2)
aws-security-audit --account-id 123456789012 --auth-method instance
```

### Advanced Options

```bash
# Audit specific services only
aws-security-audit --account-id 123456789012 --services s3,rds,vpc

# Custom configuration with parallel execution
aws-security-audit \\
  --account-id 123456789012 \\
  --security-profile custom \\
  --config-file ./custom-profile.yaml \\
  --parallel-checks 10 \\
  --output-dir ./security-reports \\
  --verbose

# Dry run (validate configuration only)
aws-security-audit --account-id 123456789012 --dry-run
```

## Security Profiles

### Built-in Profiles

- **CIS_AWS_Foundations**: Center for Internet Security AWS Foundations Benchmark v1.4.0
- **NIST_Cybersecurity**: NIST Cybersecurity Framework mapping for AWS
- **PCI_DSS**: Payment Card Industry Data Security Standard compliance
- **SOC_2**: Service Organization Control 2 compliance

### Custom Security Profiles

Create a YAML configuration file for custom security requirements:

```yaml
name: "Custom Security Profile"
description: "Organization-specific security requirements"
version: "1.0"

categories:
  s3:
    enabled: true
    checks:
      public_access:
        enabled: true
        severity: "critical"
        parameters:
          allow_public_read: false
          allow_public_write: false
      encryption:
        enabled: true
        severity: "high"
        parameters:
          require_kms: true
          allow_s3_managed: false
  
  ec2:
    enabled: true
    checks:
      imds_v2:
        enabled: true
        severity: "medium"
        parameters:
          require_imds_v2: true
```

## Security Checks Coverage

### S3 (Simple Storage Service)
- Bucket public access blocking
- Encryption at rest (KMS/AES-256)
- Access logging configuration
- Versioning and MFA delete

### EC2 (Elastic Compute Cloud)
- Instance Metadata Service v2 (IMDSv2)
- Termination protection
- Detailed monitoring
- EBS volume encryption

### Security Groups
- Unrestricted ingress rules (0.0.0.0/0)
- Overly permissive egress rules
- Unused security groups
- SSH/RDP access restrictions

### VPC (Virtual Private Cloud)
- VPC Flow Logs
- Default VPC usage
- DNS resolution settings
- VPC endpoints configuration

### RDS (Relational Database Service)
- Encryption at rest and in transit
- Public accessibility
- Automated backups configuration
- Multi-AZ deployment
- Deletion protection

### DynamoDB
- Encryption at rest with KMS
- Point-in-time recovery
- Auto scaling configuration
- Global tables setup

### EKS (Elastic Kubernetes Service)
- Cluster endpoint access control
- Control plane logging
- Node group security
- Kubernetes version

### ElastiCache
- Encryption in transit and at rest
- Subnet groups configuration
- Authentication tokens
- Backup configuration

### KMS (Key Management Service)
- Key rotation enablement
- Key policy analysis
- Key usage and lifecycle

### Load Balancers
- SSL/TLS configuration
- Access logging
- Deletion protection
- Security groups assignment

## Required AWS Permissions

The tool requires read-only permissions across AWS services. Here's a minimal IAM policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketPolicy",
        "s3:GetBucketEncryption",
        "s3:GetBucketLogging",
        "s3:GetBucketVersioning",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeInstances",
        "ec2:DescribeImages",
        "ec2:DescribeVolumes",
        "ec2:DescribeVpcs",
        "ec2:DescribeFlowLogs",
        "eks:DescribeCluster",
        "eks:ListClusters",
        "eks:DescribeNodegroup",
        "elasticache:DescribeCacheClusters",
        "elasticache:DescribeReplicationGroups",
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters",
        "dynamodb:DescribeTable",
        "dynamodb:ListTables",
        "kms:ListKeys",
        "kms:GetKeyPolicy",
        "kms:DescribeKey",
        "elbv2:DescribeLoadBalancers",
        "elbv2:DescribeListeners",
        "elb:DescribeLoadBalancers"
      ],
      "Resource": "*"
    }
  ]
}
```

## Report Formats

### Markdown Report
Human-readable report with executive summary, findings breakdown, and detailed results.

### JSON Report
Machine-readable structured data including:
- Account information and assessment metadata
- Overall score and risk level
- Category breakdown with statistics
- Detailed findings with evidence and remediation

### CSV Report
Tabular format for spreadsheet analysis:
- Flat structure with one finding per row
- Suitable for pivot tables and data analysis
- Easy integration with existing reporting tools

## Exit Codes

- `0`: Success (audit completed)
- `1`: Error (configuration, authentication, or execution failure)
- `2`: Warning (audit completed but high failure rate detected)
- `130`: Interrupted (CTRL+C)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes following the existing code structure
4. Add tests for new functionality
5. Submit a pull request

## Security Considerations

- The tool requires only read-only AWS permissions
- Credentials are handled securely using boto3 standard practices
- Sensitive data is masked in reports
- Tool usage is logged for audit trails

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
1. Check the documentation
2. Review existing issues
3. Create a new issue with detailed information

## Changelog

### Version 1.0.0
- Initial release
- Support for 10 AWS services
- 4 built-in security profiles
- 3 report formats
- Parallel execution support