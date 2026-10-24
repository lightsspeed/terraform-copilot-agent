"""Unit tests for SafetyPolicy and CommandSpec."""

import pytest

from terraform_copilot_agent.security.exceptions import (
    ForbiddenCommandError,
    SensitiveFileError,
)
from terraform_copilot_agent.security.policy import (
    CommandSpec,
    SafetyPolicy,
)


# --- Command Allowlist Tests ---

def test_approved_fmt_command() -> None:
    """terraform fmt -check is approved and converts to args list."""
    cmd = SafetyPolicy.validate_command("fmt", ["-check"])
    assert cmd.to_args_list() == ["terraform", "fmt", "-check"]


def test_approved_fmt_with_target_file() -> None:
    """terraform fmt -check with valid target file is approved."""
    cmd = SafetyPolicy.validate_command("fmt", ["-check"], "main.tf")
    assert cmd.to_args_list() == ["terraform", "fmt", "-check", "main.tf"]


def test_approved_init_command() -> None:
    """terraform init -backend=false is approved."""
    cmd = SafetyPolicy.validate_command("init", ["-backend=false"])
    assert cmd.to_args_list() == ["terraform", "init", "-backend=false"]


def test_approved_validate_command() -> None:
    """terraform validate -json is approved."""
    cmd = SafetyPolicy.validate_command("validate", ["-json"])
    assert cmd.to_args_list() == ["terraform", "validate", "-json"]


@pytest.mark.parametrize("subcmd", [
    "apply",
    "destroy",
    "import",
    "state",
    "plan",
    "refresh",
    "taint",
    "untaint",
    "push",
    "console",
    "login",
])
def test_reject_mutating_or_unapproved_subcommands(subcmd: str) -> None:
    """State-altering or unapproved subcommands are rejected."""
    with pytest.raises(ForbiddenCommandError):
        SafetyPolicy.validate_command(subcmd)


@pytest.mark.parametrize("subcmd,flags", [
    ("fmt", ["-write=true"]),
    ("fmt", ["-recursive"]),
    ("init", ["-backend=true"]),
    ("init", ["-upgrade"]),
    ("validate", ["-no-color"]),
    ("validate", ["-json", "-extra"]),
])
def test_reject_unapproved_flags(subcmd: str, flags: list[str]) -> None:
    """Flags not in the strict closed allowlist are rejected."""
    with pytest.raises(ForbiddenCommandError):
        SafetyPolicy.validate_command(subcmd, flags)


def test_reject_target_path_on_init_and_validate() -> None:
    """Positional target paths on init or validate are rejected."""
    with pytest.raises(ForbiddenCommandError):
        SafetyPolicy.validate_command("init", ["-backend=false"], target_path="main.tf")

    with pytest.raises(ForbiddenCommandError):
        SafetyPolicy.validate_command("validate", ["-json"], target_path="main.tf")


@pytest.mark.parametrize("injection", [
    "fmt; rm -rf /",
    "fmt && touch hacked",
    "fmt | grep foo",
    "fmt `id`",
    "fmt\ncat /etc/passwd",
])
def test_reject_shell_metacharacters_in_subcommand(injection: str) -> None:
    """Shell metacharacters in subcommand raise ForbiddenCommandError."""
    with pytest.raises(ForbiddenCommandError):
        SafetyPolicy.validate_command(injection)


@pytest.mark.parametrize("injection", [
    "-check; whoami",
    "-check && echo 1",
    "-check | tee log",
    "-backend=false\nls",
])
def test_reject_shell_metacharacters_in_flags(injection: str) -> None:
    """Shell metacharacters in flags raise ForbiddenCommandError."""
    with pytest.raises(ForbiddenCommandError):
        SafetyPolicy.validate_command("fmt", [injection])


def test_reject_shell_metacharacters_in_target_path() -> None:
    """Shell metacharacters in target path raise ForbiddenCommandError."""
    with pytest.raises(ForbiddenCommandError):
        SafetyPolicy.validate_command("fmt", ["-check"], target_path="main.tf; rm -rf /")


# --- Sensitive File Policy Tests ---

@pytest.mark.parametrize("sensitive_file", [
    "terraform.tfstate",
    "terraform.tfstate.backup",
    "env.tfstate.123",
    "TERRAFORM.TFSTATE",
    "TERRAFORM.TFSTATE.BACKUP",
    "infra.tfplan",
    "PRODUCTION.TFPLAN",
    ".env",
    ".env.local",
    ".env.prod",
    ".ENV",
    "id_rsa",
    "id_rsa.pub",
    "id_ed25519",
    "server.key",
    "SERVER.KEY",
    "certificate.pem",
    "bundle.pkcs12",
    "keystore.pfx",
    "aws_credentials",
    "credentials.json",
    "my_secret.txt",
    "secret_config.hcl",
    "sub/dir/terraform.tfstate",
])
def test_sensitive_file_blocking(sensitive_file: str) -> None:
    """Known sensitive file patterns and case variations are identified and blocked."""
    assert SafetyPolicy.is_sensitive_filename(sensitive_file) is True
    with pytest.raises(SensitiveFileError):
        SafetyPolicy.assert_safe_file_access(sensitive_file)


@pytest.mark.parametrize("safe_file", [
    "main.tf",
    "variables.tf",
    "outputs.tf",
    "versions.tf",
    "terraform.tf",
    "README.md",
    "modules/vpc/main.tf",
    "modules/security/outputs.tf",
])
def test_safe_file_allowed(safe_file: str) -> None:
    """Safe standard Terraform and documentation files are permitted."""
    assert SafetyPolicy.is_sensitive_filename(safe_file) is False
    # Does not raise
    SafetyPolicy.assert_safe_file_access(safe_file)
