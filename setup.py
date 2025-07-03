"""
Legacy setup.py for backward compatibility.

Modern Python packaging should use pyproject.toml instead.
This file is kept for compatibility with older pip versions.
"""

from setuptools import setup, find_packages

# For modern Python packaging, all configuration is in pyproject.toml
# This setup.py is kept for backward compatibility
setup(
    name="aws-security-audit",
    version="1.0.0",
    description="Comprehensive AWS security audit tool",
    author="Security Compliance Team",
    packages=find_packages(),
    install_requires=[
        "boto3>=1.26.0",
        "botocore>=1.29.0",
        "click>=8.0.0",
        "PyYAML>=6.0",
        "jinja2>=3.0.0",
        "colorama>=0.4.0",
        "tabulate>=0.9.0",
        "tqdm>=4.64.0",
        "python-dateutil>=2.8.0",
    ],
    entry_points={
        "console_scripts": [
            "aws-security-audit=aws_security_audit.cli:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)