"""Secret, token, and credential redaction for Terraform outputs and logs.

Note:
    Regex-based redaction is a defense-in-depth, best-effort mitigation.
    It does not provide a complete data loss prevention (DLP) guarantee.
    Never deliberately output or pass high-entropy production secrets into
    the application.
"""

import re

# AWS Access Key IDs (AKIA, ASIA, AROA, AIPA followed by 16 alphanumeric characters)
AWS_ACCESS_KEY_REGEX = re.compile(r"\b(AKIA|ASIA|AROA|AIPA)[0-9A-Z]{16}\b")

# AWS Secret Access Key heuristics (40 base64 chars preceded by key label)
AWS_SECRET_KEY_REGEX = re.compile(
    r"(?i)(aws_secret_access_key|secret_key|aws_secret)\s*([:=]\s*)[\"']?([A-Za-z0-9/+=]{40})[\"']?"
)

# PEM/OpenSSH private key blocks
PRIVATE_KEY_BLOCK_REGEX = re.compile(
    r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----"
)

# Bearer tokens (Authorization headers or tokens)
BEARER_TOKEN_REGEX = re.compile(r"(?i)\bBearer\s+([A-Za-z0-9_\-\.]{20,})\b")

# Generic credential assignments (e.g., password = "...", db_password = "...", api_key = "...")
CREDENTIAL_ASSIGNMENT_REGEX = re.compile(
    r"(?i)\b([A-Za-z0-9_.-]*(?:password|passwd|pass|token|secret|api[_-]?key|client[_-]?secret)[A-Za-z0-9_.-]*)\s*([:=]\s*)[\"']?(?!\[REDACTED_)([^\"'\s]{6,})[\"']?"
)

# Terraform variable blocks with default values for sensitive variables
TF_VARIABLE_DEFAULT_REGEX = re.compile(
    r"(?i)(variable\s+[\"'][^\"']*(?:pass|token|secret|api[_-]?key)[^\"']*[\"']\s*\{[\s\S]*?default\s*=\s*)[\"'](?!\[REDACTED_)[^\"']+[\"']"
)


class Redactor:
    """Sanitizes text by redacting common secret and credential patterns."""

    @classmethod
    def redact(cls, text: str) -> str:
        """Mask sensitive keys, tokens, and credentials in the provided text.

        Preserves normal Terraform diagnostic text, resource definitions,
        line numbers, and error messages.

        Args:
            text: Arbitrary string containing logs, diagnostics, or configuration.

        Returns:
            Sanitized string with identified credentials replaced by redaction markers.
        """
        if not text:
            return text

        # 1. Redact full private key blocks first to prevent inner patterns matching fragments
        redacted = PRIVATE_KEY_BLOCK_REGEX.sub("[REDACTED_PRIVATE_KEY]", text)

        # 2. Redact AWS Access Key IDs
        redacted = AWS_ACCESS_KEY_REGEX.sub("[REDACTED_AWS_KEY]", redacted)

        # 3. Redact AWS Secret Keys
        redacted = AWS_SECRET_KEY_REGEX.sub(r'\1\2"[REDACTED_AWS_SECRET]"', redacted)

        # 4. Redact Bearer tokens
        redacted = BEARER_TOKEN_REGEX.sub("Bearer [REDACTED_BEARER_TOKEN]", redacted)

        # 5. Redact generic credential assignments
        redacted = CREDENTIAL_ASSIGNMENT_REGEX.sub(r'\1\2"[REDACTED_CREDENTIAL]"', redacted)

        # 6. Redact Terraform variable default values for sensitive variables
        redacted = TF_VARIABLE_DEFAULT_REGEX.sub(r'\1"[REDACTED_CREDENTIAL]"', redacted)

        return redacted
