import re
from urllib.parse import urlsplit, urlunsplit

from django.core.exceptions import ValidationError

_CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f]")
_UNSAFE_TEXT = re.compile(r"[<>\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
MAX_URL_LENGTH = 500

SERVICE_URL_SCHEMES = ("http", "https", "ssh", "sftp", "postgresql", "mysql", "mongodb", "redis")
ICON_URL_SCHEMES = ("https",)


def validate_safe_text(value: str) -> None:
    """Reject markup brackets and control characters in free-text names.

    React escapes output, but names also flow into CSV/Excel/PDF exports and logs, so we
    refuse the dangerous characters at the door instead of relying on every sink escaping.
    """
    if _UNSAFE_TEXT.search(value):
        raise ValidationError("Contains characters that are not allowed (< > or control characters).")


def normalize_url(value: str, *, schemes: tuple[str, ...]) -> str:
    """Validate and normalize a URL. Returns the normalized string or raises ValidationError.

    Rules: allow-listed scheme only (blocks javascript:, data:, file:, ...), a host is required,
    no embedded credentials (user:pass@host would leak a secret into a plain-text catalogue),
    no whitespace/control characters, valid port, bounded length.
    """
    value = (value or "").strip()
    if not value:
        raise ValidationError("This field may not be blank.")
    if len(value) > MAX_URL_LENGTH:
        raise ValidationError(f"URL is too long (max {MAX_URL_LENGTH} characters).")
    if _CONTROL_OR_SPACE.search(value):
        raise ValidationError("URL must not contain spaces or control characters.")
    try:
        parts = urlsplit(value)
        port = parts.port  # raises ValueError for non-numeric / out-of-range ports
    except ValueError:
        raise ValidationError("Enter a valid URL.")
    if parts.scheme.lower() not in schemes:
        raise ValidationError(f"URL scheme must be one of: {', '.join(schemes)}.")
    if not parts.hostname:
        raise ValidationError("URL must include a host name.")
    if "@" in parts.netloc:
        raise ValidationError("URL must not contain embedded credentials.")
    if port is not None and not (1 <= port <= 65535):
        raise ValidationError("URL port must be between 1 and 65535.")
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, parts.fragment))
