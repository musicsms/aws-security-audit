"""
AWS Security Audit Report Generation Module

This module provides functionality for generating security audit reports
in various formats (JSON, CSV, Markdown) based on security check results.
"""

from .report_generator import ReportGenerator

__all__ = ["ReportGenerator"]