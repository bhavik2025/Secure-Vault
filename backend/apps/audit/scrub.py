"""Defence-in-depth scrubber for audit metadata.

Callers should never pass secrets in the first place; this makes a mistake non-fatal by
redacting any value whose key looks sensitive. It errs on the side of over-redaction.

Three layers:
  1. key names that look sensitive (including cryptographic-material names: dek, kek, wrapped,
     blind, cipher, ...),
  2. raw bytes are never rendered (``str(b"...")`` would print the content),
  3. string values that look like key material (long, unbroken, mixed letters and digits)
     are redacted even under an innocent key name.
"""
import re

REDACTED = "[REDACTED]"
_SENSITIVE_KEY = re.compile(
    r"pass|secret|token|key|auth|cookie|session|credential|plaintext|cipher|nonce|hash|otp|pin"
    r"|dek|kek|wrapped|blind|private|bearer",
    re.IGNORECASE,
)
# 40+ unbroken base64/hex/url-safe characters containing both a letter and a digit.
_KEY_LIKE_VALUE = re.compile(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9+/=_-]{40,}$")
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
    if isinstance(value, (bytes, bytearray, memoryview)):
        return REDACTED
    if isinstance(value, str):
        return REDACTED if _KEY_LIKE_VALUE.match(value[:_MAX_STR]) else value[:_MAX_STR]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:_MAX_STR]
