# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-01-XX

### Added
- Initial release of AWS Security Audit Tool
- Comprehensive security checks for 10 AWS services (S3, EC2, RDS, VPC, EKS, ElastiCache, DynamoDB, KMS, Security Groups, Load Balancers)
- Multiple security profiles: CIS AWS Foundations, NIST Cybersecurity, PCI DSS, SOC 2, and custom profiles
- Support for multiple authentication methods
- Reports in Markdown, JSON, and CSV formats
- Parallel execution capability
- Command-line interface with comprehensive options

### Changed
- Modernized package structure following Python best practices
- Added `pyproject.toml` for modern Python packaging
- Improved package imports and exports
- Added proper `.gitignore` file
- Enhanced documentation and metadata

### Infrastructure
- Added support for module execution (`python -m aws_security_audit`)
- Added type hints support (`py.typed` marker)
- Configured development tools (black, isort, mypy, pytest)
- Added comprehensive project metadata 