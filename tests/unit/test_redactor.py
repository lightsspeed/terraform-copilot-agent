"""Unit tests for Redactor."""

from terraform_copilot_agent.security.redactor import Redactor


def test_redact_aws_access_key() -> None:
    """AWS Access Key IDs are masked."""
    text = "Error configuring provider: InvalidAccessKeyId for AKIAIOSFODNN7EXAMPLE in region us-east-1"
    redacted = Redactor.redact(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "[REDACTED_AWS_KEY]" in redacted
    assert "InvalidAccessKeyId" in redacted


def test_redact_aws_secret_access_key() -> None:
    """AWS Secret Access Keys are masked."""
    text = 'provider "aws" {\n  access_key = "AKIA1111111111111111"\n  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n}'
    redacted = Redactor.redact(text)
    assert "AKIA1111111111111111" not in redacted
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in redacted
    assert "[REDACTED_AWS_KEY]" in redacted
    assert "[REDACTED_AWS_SECRET]" in redacted


def test_redact_private_key_block() -> None:
    """Private key blocks are masked."""
    pem_content = """
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA04qF3r...
...fake_key_material...
-----END RSA PRIVATE KEY-----
"""
    log = f"Failed to parse key:\n{pem_content}\nCheck file format."
    redacted = Redactor.redact(log)
    assert "-----BEGIN RSA PRIVATE KEY-----" not in redacted
    assert "fake_key_material" not in redacted
    assert "[REDACTED_PRIVATE_KEY]" in redacted
    assert "Failed to parse key:" in redacted


def test_redact_bearer_token() -> None:
    """HTTP Bearer tokens are masked."""
    header = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abcdef1234567890"
    redacted = Redactor.redact(header)
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abcdef1234567890" not in redacted
    assert "Bearer [REDACTED_BEARER_TOKEN]" in redacted


def test_redact_generic_credentials() -> None:
    """Password and token assignments are masked."""
    config = 'variable "db_pass" {\n  default = "SuperSecretPassword123"\n}\napi_key = "abcdef1234567890"'
    redacted = Redactor.redact(config)
    assert "SuperSecretPassword123" not in redacted
    assert "abcdef1234567890" not in redacted
    assert '[REDACTED_CREDENTIAL]' in redacted


def test_preserve_normal_diagnostic_text() -> None:
    """Ordinary Terraform diagnostics and syntax errors are preserved intact."""
    diagnostic = """
Error: Missing newline after argument

  on main.tf line 4, in resource "aws_s3_bucket" "example":
   4:   bucket = "my-test-bucket-2026" acl = "private"

An argument definition must end with a newline.
"""
    redacted = Redactor.redact(diagnostic)
    assert redacted == diagnostic


def test_empty_and_clean_text() -> None:
    """Empty and benign strings pass through without modification."""
    assert Redactor.redact("") == ""
    clean = "Terraform configuration is valid."
    assert Redactor.redact(clean) == clean
