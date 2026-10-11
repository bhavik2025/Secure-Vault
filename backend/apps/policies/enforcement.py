"""Server-side policy enforcement helpers.

Every module that needs a policy decision calls these, so the rule lives in one place and
cannot be bypassed by skipping the UI. Call sites:
  * account passwords  -> apps.policies.validators (live now, via Django's password validation)
  * vault credentials  -> check_password_rules / default_expiry_date (vault phase)
  * view-once sharing  -> ensure_view_once_allowed (sharing phase)
  * device gate        -> device_trust_required (device phase)
"""
from dataclasses import dataclass
from datetime import date, timedelta

from apps.core.exceptions import PolicyViolation

from .models import DEFAULTS, SecurityPolicy


@dataclass(frozen=True)
class BuiltinPolicy:
    """Fail-safe used when an organization has no active policy."""

    name: str = "Built-in default"
    min_length: int = DEFAULTS["min_length"]
    require_symbols: bool = DEFAULTS["require_symbols"]
    max_age_days: int | None = DEFAULTS["max_age_days"]
    allow_view_once: bool = DEFAULTS["allow_view_once"]
    require_device_trust: bool = DEFAULTS["require_device_trust"]
    source: str = "builtin_default"


def get_effective_policy(organization_id):
    """The active policy for an organization, or the built-in defaults. Never returns None."""
    if organization_id is not None:
        policy = SecurityPolicy.objects.filter(organization_id=organization_id, is_active=True).first()
        if policy:
            return policy
    return BuiltinPolicy()


def check_password_rules(password: str, policy) -> list[str]:
    """Human-readable violations of the policy's password rules (empty list = compliant)."""
    problems = []
    if len(password) < policy.min_length:
        problems.append(f"Password must be at least {policy.min_length} characters long.")
    if policy.require_symbols and not any(not c.isalnum() and not c.isspace() for c in password):
        problems.append("Password must contain at least one symbol (for example ! @ # $ %).")
    return problems


def default_expiry_date(policy, today: date | None = None) -> date | None:
    """Default expiry for a newly stored credential; None when the policy sets no maximum age."""
    if policy.max_age_days is None:
        return None
    return (today or date.today()) + timedelta(days=policy.max_age_days)


def ensure_view_once_allowed(policy) -> None:
    if not policy.allow_view_once:
        raise PolicyViolation("view_once_disabled", "View-once sharing is disabled by your organization's security policy.")


def device_trust_required(policy) -> bool:
    return bool(policy.require_device_trust)
