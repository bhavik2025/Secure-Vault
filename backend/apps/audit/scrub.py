"""Defence-in-depth scrubber for audit metadata.

Callers should never pass secrets in the first place; this makes a mistake non-fatal by
redacting any value whose key looks sensitive. It errs on the side of over-redaction.
"""
import re

REDACTED = "[REDACTED]"
_SENSITIVE_KEY = re.compile(
    r"pass|secret|token|key|auth|cookie|session|credential|plaintext|ciphertext|nonce|hash|otp|pin",
    re.IGNORECASE,
)
_MAX_STR = 500
_MAX_DEPTH = 5


def scrub(value, _depth=0):
    if _depth > _MAX_DEPTH:
        return REDACTED
    if isinstance(value, dict):
        return {
            str(k): (REDACTED if _SENSITIVE_KEY.search(str(k)) else scrub(v, _depth + 1)) for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [scrub(v, _depth + 1) for v in value[:50]]
    if isinstance(value, str):
        return value[:_MAX_STR]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:_MAX_STR]
