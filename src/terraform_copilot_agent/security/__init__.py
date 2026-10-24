"""Security and policy enforcement package for Terraform Copilot Agent."""

from terraform_copilot_agent.security.exceptions import (
    ForbiddenCommandError,
    PathTraversalError,
    SecurityError,
    SensitiveFileError,
    SymlinkEscapeError,
)
from terraform_copilot_agent.security.path_validator import PathValidator
from terraform_copilot_agent.security.policy import (
    APPROVED_COMMAND_SPECS,
    FORBIDDEN_SUBCOMMANDS,
    SENSITIVE_FILE_PATTERNS,
    CommandSpec,
    SafetyPolicy,
)
from terraform_copilot_agent.security.redactor import Redactor

__all__ = [
    "SecurityError",
    "PathTraversalError",
    "SymlinkEscapeError",
    "SensitiveFileError",
    "ForbiddenCommandError",
    "PathValidator",
    "SafetyPolicy",
    "CommandSpec",
    "APPROVED_COMMAND_SPECS",
    "FORBIDDEN_SUBCOMMANDS",
    "SENSITIVE_FILE_PATTERNS",
    "Redactor",
]
