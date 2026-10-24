"""Security and policy exceptions for Terraform Copilot Agent."""


class SecurityError(Exception):
    """Base exception for all security and policy violations."""


class PathTraversalError(SecurityError):
    """Raised when an operation attempts to access paths outside the workspace root."""


class SymlinkEscapeError(SecurityError):
    """Raised when a symlink resolves to a target outside the workspace root."""


class SensitiveFileError(SecurityError):
    """Raised when an operation attempts to access blocked sensitive files (e.g., state, credentials)."""


class ForbiddenCommandError(SecurityError):
    """Raised when an unapproved subcommand, unapproved flag, or arbitrary command execution is attempted."""
