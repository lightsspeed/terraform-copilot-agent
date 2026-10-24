"""Safety policies, command allowlists, and sensitive file protections."""

import fnmatch
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from terraform_copilot_agent.security.exceptions import (
    ForbiddenCommandError,
    SensitiveFileError,
)

# Shell meta-characters that could indicate injection attempts
SHELL_METASYMBOLS_REGEX = re.compile(r"[;&|`$><\r\n]")

# Strict closed allowlist of approved Terraform subcommands and their allowed flags
APPROVED_COMMAND_SPECS: dict[str, set[str]] = {
    "fmt": {"-check"},
    "init": {"-backend=false"},
    "validate": {"-json"},
}

# Explicitly forbidden mutating or unvetted subcommands
FORBIDDEN_SUBCOMMANDS: set[str] = {
    "apply",
    "destroy",
    "import",
    "state",
    "taint",
    "untaint",
    "refresh",
    "plan",
    "push",
    "login",
    "logout",
    "console",
    "force-unlock",
}

# Sensitive file glob patterns (matched case-insensitively)
SENSITIVE_FILE_PATTERNS: tuple[str, ...] = (
    "*.tfstate",
    "*.tfstate.*",
    "*.tfplan",
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.pkcs12",
    "*.pfx",
    "*.p12",
    "id_rsa*",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
    "*credentials*",
    "*credential*",
    "*.secret",
    "*secret*",
)


class CommandSpec(BaseModel):
    """Structured, validated specification for allowlisted Terraform commands."""

    executable: Literal["terraform"] = "terraform"
    subcommand: str
    flags: list[str] = Field(default_factory=list)
    target_path: str | None = None

    @field_validator("subcommand")
    @classmethod
    def validate_subcommand(cls, value: str) -> str:
        sub = value.strip().lower()
        if SHELL_METASYMBOLS_REGEX.search(sub):
            raise ForbiddenCommandError(f"Shell metacharacters detected in subcommand: '{value}'")
        if sub in FORBIDDEN_SUBCOMMANDS:
            raise ForbiddenCommandError(
                f"Terraform command '{sub}' is strictly forbidden in V1 safety policy"
            )
        if sub not in APPROVED_COMMAND_SPECS:
            raise ForbiddenCommandError(
                f"Terraform command '{sub}' is not in the allowlist. Allowed: {list(APPROVED_COMMAND_SPECS.keys())}"
            )
        return sub

    @field_validator("flags")
    @classmethod
    def validate_flags(cls, flags: list[str], info) -> list[str]:
        sub = info.data.get("subcommand")
        if not sub or sub not in APPROVED_COMMAND_SPECS:
            return flags

        allowed_flags = APPROVED_COMMAND_SPECS[sub]
        for flag in flags:
            f = flag.strip()
            if SHELL_METASYMBOLS_REGEX.search(f):
                raise ForbiddenCommandError(f"Shell metacharacters detected in flag: '{flag}'")
            if f not in allowed_flags:
                raise ForbiddenCommandError(
                    f"Flag '{flag}' is not permitted for 'terraform {sub}'. Allowed flags: {allowed_flags}"
                )
        return flags

    @field_validator("target_path")
    @classmethod
    def validate_target_path(cls, value: str | None, info) -> str | None:
        if value is None:
            return None
        sub = info.data.get("subcommand")
        if sub != "fmt":
            raise ForbiddenCommandError(f"Positional target path is not permitted for 'terraform {sub}'")
        if SHELL_METASYMBOLS_REGEX.search(value):
            raise ForbiddenCommandError(f"Shell metacharacters detected in target path: '{value}'")
        return value

    def to_args_list(self) -> list[str]:
        """Convert validated specification into a safe argument list for subprocess execution."""
        args = [self.executable, self.subcommand]
        args.extend(self.flags)
        if self.target_path:
            args.append(self.target_path)
        return args


class SafetyPolicy:
    """Enforces command allowlisting and sensitive file blocking."""

    @staticmethod
    def is_sensitive_filename(path_or_filename: str | Path) -> bool:
        """Check if a filename or path matches any blocked sensitive pattern.

        Case-insensitive matching to protect against filesystem inconsistencies.
        """
        name = Path(path_or_filename).name.lower()
        # Also test the relative string in case patterns match directories or relative segments
        full_str = str(path_or_filename).replace("\\", "/").lower()

        for pattern in SENSITIVE_FILE_PATTERNS:
            if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(full_str, pattern):
                return True
        return False

    @classmethod
    def assert_safe_file_access(cls, path_or_filename: str | Path) -> None:
        """Raise SensitiveFileError if the file matches any sensitive pattern.

        Args:
            path_or_filename: Path or filename to check.

        Raises:
            SensitiveFileError: If the file is deemed sensitive.
        """
        if cls.is_sensitive_filename(path_or_filename):
            raise SensitiveFileError(
                f"Access to sensitive file '{path_or_filename}' is strictly blocked by safety policy"
            )

    @classmethod
    def validate_command(
        cls,
        subcommand: str,
        flags: list[str] | None = None,
        target_path: str | None = None,
    ) -> CommandSpec:
        """Validate and construct an approved CommandSpec.

        Args:
            subcommand: Terraform subcommand (e.g., 'fmt', 'init', 'validate').
            flags: Optional list of flags.
            target_path: Optional target path (only allowed for 'fmt').

        Returns:
            Validated CommandSpec instance.

        Raises:
            ForbiddenCommandError: If subcommand, flags, or targets violate the safety policy.
        """
        return CommandSpec(
            subcommand=subcommand,
            flags=flags or [],
            target_path=target_path,
        )
