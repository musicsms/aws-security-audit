"""
AWS Security Audit Report Generator

This module provides functionality to generate comprehensive security audit reports
in multiple formats (JSON, CSV, Markdown) based on security check results.
"""

import json
import csv
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import asdict

from jinja2 import Template
from tabulate import tabulate

from ..checks.base_checks import CheckResult, CheckStatus
from ..config_manager import SecurityProfile, Severity


class ReportGenerator:
    """Generates security audit reports in multiple formats."""
    
    def __init__(self, account_id: str, profile: SecurityProfile):
        """
        Initialize the report generator.
        
        Args:
            account_id: AWS account ID being audited
            profile: Security profile used for the audit
        """
        self.account_id = account_id
        self.profile = profile
        self.logger = logging.getLogger(__name__)
        
        # Report metadata
        self.report_metadata = {
            'account_id': account_id,
            'profile_name': profile.name,
            'profile_version': profile.version,
            'profile_description': profile.description,
            'generated_at': datetime.utcnow().isoformat() + 'Z',
            'generator': 'AWS Security Audit Tool v1.0.0'
        }
    
    def save_reports(self, results: List[CheckResult], output_dir: str, formats: List[str], 
                     save_raw_evidence: bool = True, filter_sensitive: bool = True) -> Dict[str, str]:
        """
        Save security audit reports in specified formats.
        
        Args:
            results: List of security check results
            output_dir: Directory to save reports
            formats: List of output formats ('json', 'csv', 'markdown')
            save_raw_evidence: Whether to save raw evidence to separate JSON file
            filter_sensitive: Whether to filter sensitive data from raw evidence
            
        Returns:
            Dictionary mapping format names to file paths
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"aws_security_audit_{self.account_id}_{timestamp}"
        
        saved_files = {}
        
        for format_type in formats:
            if format_type == 'json':
                filepath = output_path / f"{base_filename}.json"
                self._save_json_report(results, filepath)
                saved_files['json'] = str(filepath)
                
            elif format_type == 'csv':
                filepath = output_path / f"{base_filename}.csv"
                self._save_csv_report(results, filepath)
                saved_files['csv'] = str(filepath)
                
            elif format_type == 'markdown':
                filepath = output_path / f"{base_filename}.md"
                self._save_markdown_report(results, filepath)
                saved_files['markdown'] = str(filepath)
                
            else:
                self.logger.warning(f"Unsupported format: {format_type}")
        
        # Generate raw evidence file if requested
        if save_raw_evidence:
            raw_evidence_filepath = output_path / f"{base_filename}_raw_evidence.json"
            self._save_raw_evidence_json(results, raw_evidence_filepath, filter_sensitive)
            saved_files['raw_evidence'] = str(raw_evidence_filepath)
        
        self.logger.info(f"Generated {len(saved_files)} report(s) in {output_dir}")
        return saved_files
    
    def _save_json_report(self, results: List[CheckResult], filepath: Path) -> None:
        """Save report in JSON format."""
        # Convert results to dictionaries for JSON serialization
        results_data = []
        for result in results:
            result_dict = asdict(result)
            # Convert enums to strings for JSON serialization
            result_dict['status'] = result.status.value
            result_dict['severity'] = result.severity.value
            
            # Remove raw evidence from main report - it's saved separately
            if 'raw_evidence' in result_dict:
                del result_dict['raw_evidence']
            
            results_data.append(result_dict)
        
        # Create comprehensive report structure
        report_data = {
            'metadata': self.report_metadata,
            'summary': self._generate_summary(results),
            'results': results_data,
            'raw_evidence_note': 'Detailed API responses available in separate *_raw_evidence.json file'
        }
        
        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        self.logger.info(f"JSON report saved to {filepath}")
    
    def _save_raw_evidence_json(self, results: List[CheckResult], filepath: Path, filter_sensitive: bool = True) -> None:
        """Save raw evidence in separate JSON format."""
        # Organize raw evidence by service and check
        raw_evidence_by_service = {}
        raw_evidence_by_check = {}
        
        for result in results:
            if result.raw_evidence:
                # Extract service from check_id (e.g., "EC2.1" -> "ec2")
                service = result.check_id.split('.')[0].lower() if result.check_id else 'unknown'
                
                # Filter sensitive data if requested
                evidence = self._filter_sensitive_data(result.raw_evidence) if filter_sensitive else result.raw_evidence
                
                evidence_entry = {
                    'check_id': result.check_id,
                    'resource_id': result.resource_id,
                    'region': result.region,
                    'status': result.status.value,
                    'severity': result.severity.value,
                    'raw_evidence': evidence,
                    'timestamp': datetime.utcnow().isoformat() + 'Z'
                }
                
                # Group by service
                if service not in raw_evidence_by_service:
                    raw_evidence_by_service[service] = []
                raw_evidence_by_service[service].append(evidence_entry)
                
                # Group by check
                if result.check_id not in raw_evidence_by_check:
                    raw_evidence_by_check[result.check_id] = []
                raw_evidence_by_check[result.check_id].append(evidence_entry)
        
        # Create comprehensive raw evidence structure
        raw_evidence_data = {
            'metadata': {
                'account_id': self.account_id,
                'profile_name': self.profile.name,
                'generated_at': datetime.utcnow().isoformat() + 'Z',
                'evidence_type': 'raw_api_responses',
                'sensitive_data_filtered': filter_sensitive,
                'total_evidence_entries': sum(len(entries) for entries in raw_evidence_by_service.values())
            },
            'raw_evidence_by_service': raw_evidence_by_service,
            'raw_evidence_by_check': raw_evidence_by_check
        }
        
        with open(filepath, 'w') as f:
            json.dump(raw_evidence_data, f, indent=2, default=str)
        
        self.logger.info(f"Raw evidence JSON saved to {filepath}")
    
    def _save_csv_report(self, results: List[CheckResult], filepath: Path) -> None:
        """Save report in CSV format."""
        fieldnames = [
            'check_id', 'name', 'status', 'severity', 'description',
            'evidence', 'remediation', 'resource_id', 'region'
        ]
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                row = {
                    'check_id': result.check_id,
                    'name': result.name,
                    'status': result.status.value,
                    'severity': result.severity.value,
                    'description': result.description,
                    'evidence': result.evidence,
                    'remediation': result.remediation or '',
                    'resource_id': result.resource_id or '',
                    'region': result.region or ''
                }
                writer.writerow(row)
        
        self.logger.info(f"CSV report saved to {filepath}")
    
    def _save_markdown_report(self, results: List[CheckResult], filepath: Path) -> None:
        """Save report in Markdown format."""
        template_content = self._get_markdown_template()
        template = Template(template_content)
        
        # Prepare data for template
        template_data = {
            'metadata': self.report_metadata,
            'summary': self._generate_summary(results),
            'results_by_severity': self._group_results_by_severity(results),
            'results_by_status': self._group_results_by_status(results),
            'results_by_service': self._group_results_by_service(results),
            'all_results': results
        }
        
        
        rendered_content = template.render(**template_data)
        
        with open(filepath, 'w') as f:
            f.write(rendered_content)
        
        self.logger.info(f"Markdown report saved to {filepath}")
    
    def _generate_summary(self, results: List[CheckResult]) -> Dict[str, Any]:
        """Generate summary statistics for the audit results."""
        total_checks = len(results)
        
        # Count by status
        status_counts = {}
        for status in CheckStatus:
            status_counts[status.value] = sum(1 for r in results if r.status == status)
        
        # Count by severity
        severity_counts = {}
        for severity in Severity:
            severity_counts[severity.value] = sum(1 for r in results if r.severity == severity)
        
        # Calculate pass rate
        passed_checks = status_counts.get(CheckStatus.OK.value, 0)
        pass_rate = (passed_checks / total_checks * 100) if total_checks > 0 else 0
        
        # Find critical and high severity failures
        critical_failures = [r for r in results if r.severity == Severity.CRITICAL and r.status == CheckStatus.NOK]
        high_failures = [r for r in results if r.severity == Severity.HIGH and r.status == CheckStatus.NOK]
        
        return {
            'total_checks': total_checks,
            'status_counts': status_counts,
            'severity_counts': severity_counts,
            'pass_rate': round(pass_rate, 2),
            'critical_failures': len(critical_failures),
            'high_failures': len(high_failures),
            'regions_audited': list(set(r.region for r in results if r.region)),
            'services_audited': list(set(r.check_id.split('_')[0] for r in results if r.check_id))
        }
    
    def _group_results_by_severity(self, results: List[CheckResult]) -> Dict[str, List[CheckResult]]:
        """Group results by severity level."""
        grouped = {}
        for severity in Severity:
            grouped[severity.value] = [r for r in results if r.severity == severity]
        return grouped
    
    def _group_results_by_status(self, results: List[CheckResult]) -> Dict[str, List[CheckResult]]:
        """Group results by status."""
        grouped = {}
        for status in CheckStatus:
            grouped[status.value] = [r for r in results if r.status == status]
        return grouped
    
    def _group_results_by_service(self, results: List[CheckResult]) -> Dict[str, List[CheckResult]]:
        """Group results by AWS service."""
        grouped = {}
        for result in results:
            service = result.check_id.split('_')[0] if result.check_id else 'unknown'
            if service not in grouped:
                grouped[service] = []
            grouped[service].append(result)
        return grouped
    
    def _filter_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Filter sensitive data from raw evidence."""
        if not isinstance(data, dict):
            return data
        
        filtered = {}
        sensitive_keys = [
            'password', 'secret', 'key', 'token', 'credentials', 'auth',
            'private', 'confidential', 'ssn', 'credit_card', 'api_key'
        ]
        
        for key, value in data.items():
            key_lower = key.lower()
            
            # Check if key contains sensitive terms
            if any(sensitive_term in key_lower for sensitive_term in sensitive_keys):
                filtered[key] = "[REDACTED]"
            elif isinstance(value, dict):
                filtered[key] = self._filter_sensitive_data(value)
            elif isinstance(value, list):
                filtered[key] = [self._filter_sensitive_data(item) if isinstance(item, dict) else item for item in value]
            else:
                filtered[key] = value
        
        return filtered
    
    def _format_raw_evidence(self, raw_evidence: Dict[str, Any]) -> str:
        """Format raw evidence for display in text reports."""
        if not raw_evidence:
            return "No raw evidence available"
        
        formatted = []
        for key, value in raw_evidence.items():
            if isinstance(value, dict):
                formatted.append(f"**{key}:**")
                for sub_key, sub_value in value.items():
                    formatted.append(f"  - {sub_key}: {sub_value}")
            elif isinstance(value, list):
                formatted.append(f"**{key}:** {len(value)} items")
                for i, item in enumerate(value[:3]):  # Show first 3 items
                    formatted.append(f"  - [{i}]: {item}")
                if len(value) > 3:
                    formatted.append(f"  - ... and {len(value) - 3} more items")
            else:
                formatted.append(f"**{key}:** {value}")
        
        return "\n".join(formatted)
    
    def _get_markdown_template(self) -> str:
        """Get the Markdown report template."""
        return """# AWS Security Audit Report

## Report Information

- **Account ID**: {{ metadata.account_id }}
- **Security Profile**: {{ metadata.profile_name }} ({{ metadata.profile_version }})
- **Generated**: {{ metadata.generated_at }}
- **Generator**: {{ metadata.generator }}
- **Raw Evidence**: Detailed API responses available in separate `*_raw_evidence.json` file

## Executive Summary

- **Total Checks**: {{ summary.total_checks }}
- **Pass Rate**: {{ summary.pass_rate }}%
- **Critical Failures**: {{ summary.critical_failures }}
- **High Severity Failures**: {{ summary.high_failures }}
- **Regions Audited**: {{ summary.regions_audited | join(', ') }}
- **Services Audited**: {{ summary.services_audited | join(', ') }}

## Results by Status

| Status | Count | Percentage |
|--------|-------|------------|
{% for status, count in summary.status_counts.items() -%}
| {{ status }} | {{ count }} | {{ "%.1f" | format(count / summary.total_checks * 100) }}% |
{% endfor %}

## Results by Severity

| Severity | Count | Percentage |
|----------|-------|------------|
{% for severity, count in summary.severity_counts.items() -%}
| {{ severity }} | {{ count }} | {{ "%.1f" | format(count / summary.total_checks * 100) }}% |
{% endfor %}

## Critical Findings

{% if results_by_severity.critical -%}
{% for result in results_by_severity.critical -%}
{% if result.status.value == 'NOK' -%}
### {{ result.name }}

- **Check ID**: {{ result.check_id }}
- **Status**: {{ result.status.value }}
- **Resource**: {{ result.resource_id or 'N/A' }}
- **Region**: {{ result.region or 'N/A' }}
- **Description**: {{ result.description }}
- **Evidence**: {{ result.evidence }}
- **Remediation**: {{ result.remediation or 'Not specified' }}

{% endif -%}
{% endfor -%}
{% else -%}
No critical findings detected.
{% endif %}

## High Severity Findings

{% if results_by_severity.high -%}
{% for result in results_by_severity.high -%}
{% if result.status.value == 'NOK' or result.status.value == 'ERROR' -%}
### {{ result.name }}

- **Check ID**: {{ result.check_id }}
- **Status**: {{ result.status.value }}
- **Resource**: {{ result.resource_id or 'N/A' }}
- **Region**: {{ result.region or 'N/A' }}
- **Description**: {{ result.description }}
- **Evidence**: {{ result.evidence }}
- **Remediation**: {{ result.remediation or 'Not specified' }}

{% endif -%}
{% endfor -%}
{% else -%}
No high severity findings detected.
{% endif %}

## Error Status Findings

{% if results_by_status.ERROR -%}
The following checks encountered errors during execution:

{% for result in results_by_status.ERROR -%}
### {{ result.name }}

- **Check ID**: {{ result.check_id }}
- **Status**: {{ result.status.value }}
- **Resource**: {{ result.resource_id or 'N/A' }}
- **Region**: {{ result.region or 'N/A' }}
- **Description**: {{ result.description }}
- **Evidence**: {{ result.evidence }}
- **Remediation**: {{ result.remediation or 'Not specified' }}

{% if result.raw_evidence -%}
**Raw Evidence**: Available in separate `*_raw_evidence.json` file
{% endif -%}

{% endfor -%}
{% else -%}
No error findings detected.
{% endif %}

## Detailed Results by Service

{% for service, service_results in results_by_service.items() -%}
### {{ service.upper() }} Service

| Check | Status | Severity | Resource | Region |
|-------|--------|----------|----------|--------|
{% for result in service_results -%}
| {{ result.name }} | {{ result.status.value }} | {{ result.severity.value }} | {{ result.resource_id or 'N/A' }} | {{ result.region or 'N/A' }} |
{% endfor %}

{% endfor %}

## Recommendations

1. **Immediate Action Required**: Address all critical severity findings
2. **High Priority**: Resolve high severity findings within 30 days
3. **Medium Priority**: Plan remediation for medium severity findings
4. **Monitoring**: Implement continuous monitoring for identified issues
5. **Review**: Regularly review and update security configurations

## Compliance Status

Based on the {{ metadata.profile_name }} profile:
- **{{ metadata.profile_description }}**
- **Overall Compliance**: {{ summary.pass_rate }}%

---

*This report was generated by {{ metadata.generator }} on {{ metadata.generated_at }}*
"""