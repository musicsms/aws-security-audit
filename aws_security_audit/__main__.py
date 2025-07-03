"""Entry point for aws_security_audit module execution.

This allows the package to be executed as a module:
    python -m aws_security_audit
"""

from .cli import main

if __name__ == "__main__":
    main() 