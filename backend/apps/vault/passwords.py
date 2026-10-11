"""Password generation and strength estimation."""
import functools
import math
import secrets
import string
from dataclasses import dataclass

from django.contrib.auth.password_validation import CommonPasswordValidator

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"  # no quotes, backslash, space or backtick: safe in most shells/forms
AMBIGUOUS = set("Il1O0o")

MIN_LENGTH, MAX_LENGTH = 8, 128

# Labels by estimated bits of entropy.
_LABELS = ((28, "VERY_WEAK"), (36, "WEAK"), (60, "FAIR"), (80, "STRONG"))
WEAK_BELOW_BITS = 36


def generate_password(
    length: int = 20,
    *,
    lowercase: bool = True,
    uppercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    """Cryptographically secure password: every character comes from ``secrets`` (OS CSPRNG).

    One character is drawn from each selected class (so class requirements always hold), the rest
    from the union, then the order is shuffled with ``SystemRandom``. Forcing one-per-class lowers
    entropy by a negligible amount; this is the standard trade for guaranteed composition.
    """
    if not MIN_LENGTH <= length <= MAX_LENGTH:
        raise ValueError(f"Length must be between {MIN_LENGTH} and {MAX_LENGTH}.")
    pools = []
    for enabled, chars in ((lowercase, LOWER), (uppercase, UPPER), (digits, DIGITS), (symbols, SYMBOLS)):
        if enabled:
            pools.append("".join(c for c in chars if not (exclude_ambiguous and c in AMBIGUOUS)))
    if not pools:
        raise ValueError("Select at least one character class.")
    union = "".join(pools)
    chars = [secrets.choice(p) for p in pools]
    chars += [secrets.choice(union) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


@dataclass(frozen=True)
class Strength:
    bits: float
    label: str
    issues: tuple[str, ...]


def _pool_size(password: str) -> int:
    pool = 0
    if any(c in LOWER for c in password):
        pool += 26
    if any(c in UPPER for c in password):
        pool += 26
    if any(c in DIGITS for c in password):
        pool += 10
    if any(c.isascii() and not c.isalnum() for c in password):
        pool += 33  # ASCII punctuation, symbols and space
    if any(not c.isascii() for c in password):
        pool += 100  # coarse allowance for non-ASCII characters
    return max(pool, 1)


@functools.lru_cache(maxsize=1)
def _common_passwords() -> frozenset:
    # Django ships a list of ~20,000 commonly used passwords; loading it once is enough.
    return frozenset(CommonPasswordValidator().passwords)


def label_for_bits(bits: float) -> str:
    for threshold, label in _LABELS:
        if bits < threshold:
            return label
    return "VERY_STRONG"


def estimate_strength(password: str) -> Strength:
    """Heuristic entropy estimate (bits). An *upper bound*, not a proof of strength.

    bits = effective_length * log2(character-pool size), where characters that merely repeat the
    previous one or continue an ascending/descending run (``aaaa``, ``1234``, ``abcd``) count as zero,
    and passwords found in Django's common-password list are capped at ~14 bits. It cannot see
    dictionary words, names or keyboard patterns, so human-chosen passwords are overrated; truly
    random (generated) passwords are estimated well.
    """
    issues = []
    if len(password) < 8:
        issues.append("short")
    predictable = sum(
        1
        for prev, cur in zip(password, password[1:])
        if cur == prev or abs(ord(cur) - ord(prev)) == 1
    )
    effective = max(len(password) - predictable, 0)
    if predictable >= 3:
        issues.append("repeated_or_sequential_characters")
    if len({c for c in password}) == 1 or len(password) == 0:
        effective = min(effective, 1)
    pool = _pool_size(password)
    if pool <= 26 and len(password) > 0:
        issues.append("single_character_class")
    bits = effective * math.log2(pool) if pool > 1 else 0.0
    if password.lower() in _common_passwords():
        issues.append("common_password")
        bits = min(bits, 14.0)
    bits = round(bits, 1)
    return Strength(bits=bits, label=label_for_bits(bits), issues=tuple(issues))
