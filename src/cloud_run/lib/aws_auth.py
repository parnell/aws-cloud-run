from __future__ import annotations

import os

import botocore.exceptions as botocore_exceptions


def aws_auth_error_message() -> str:
    """Return a helpful message for missing/expired AWS auth."""
    profile = os.environ.get("AWS_PROFILE")
    profile_hint = f" (AWS_PROFILE={profile})" if profile else ""
    return (
        "AWS credentials are missing or expired."
        + profile_hint
        + " If you use AWS SSO, run `aws sso login` then retry."
    )


def is_aws_auth_error(e: Exception) -> bool:
    """Best-effort detection of AWS authentication/credential failures."""
    # Common botocore credential errors
    if isinstance(
        e, botocore_exceptions.NoCredentialsError | botocore_exceptions.PartialCredentialsError
    ):
        return True

    # SSO-specific errors (names vary by botocore version)
    sso_error_types = tuple(
        getattr(botocore_exceptions, name)
        for name in ("SSOTokenLoadError", "UnauthorizedSSOTokenError")
        if hasattr(botocore_exceptions, name)
    )
    if sso_error_types and isinstance(e, sso_error_types):
        return True

    # AWS service errors
    if isinstance(e, botocore_exceptions.ClientError):
        err = e.response.get("Error", {}) if getattr(e, "response", None) else {}
        code = (err.get("Code") or "").strip()
        msg = (err.get("Message") or "").strip().lower()

        if code in {
            "UnrecognizedClientException",
            "InvalidClientTokenId",
            "ExpiredToken",
            "ExpiredTokenException",
            "InvalidSignatureException",
            "IncompleteSignature",
            "MissingAuthenticationToken",
        }:
            return True

        # Heuristic: token/signature/SSO wording in message
        if any(
            k in msg
            for k in ("expired token", "security token", "invalid token", "sso", "not authorized")
        ):
            return True

    return False
