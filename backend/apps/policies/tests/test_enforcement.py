from datetime import date

import pytest
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from apps.core.exceptions import PolicyViolation, api_exception_handler
from apps.policies.enforcement import (
    BuiltinPolicy,
    check_password_rules,
    default_expiry_date,
    device_trust_required,
    ensure_view_once_allowed,
    get_effective_policy,
)
from apps.policies.models import SecurityPolicy

pytestmark = pytest.mark.django_db


def set_policy(org, **fields):
    SecurityPolicy.objects.filter(organization=org, is_active=True).update(**fields)


# --- pure rule checks ---------------------------------------------------------------------

@pytest.mark.parametrize(
    "password,min_length,symbols,n_problems",
    [
        ("Short1!", 12, True, 1),
        ("LongEnoughButNoSymbol1", 12, True, 1),
        ("short", 12, True, 2),
        ("LongEnoughPassw0rd!", 12, True, 0),
        ("alllowercaseletters", 12, False, 0),
        ("has space but no symbol", 12, True, 1),  # whitespace is not a symbol
        ("abcdefgh", 8, False, 0),
        ("abcdefg", 8, False, 1),
    ],
)
def test_check_password_rules(password, min_length, symbols, n_problems):
    policy = BuiltinPolicy(min_length=min_length, require_symbols=symbols)
    assert len(check_password_rules(password, policy)) == n_problems


def test_default_expiry_follows_max_age_and_none_means_never():
    assert default_expiry_date(BuiltinPolicy(max_age_days=30), date(2026, 1, 1)) == date(2026, 1, 31)
    assert default_expiry_date(BuiltinPolicy(max_age_days=None), date(2026, 1, 1)) is None


def test_view_once_is_blocked_when_policy_disallows_it():
    ensure_view_once_allowed(BuiltinPolicy(allow_view_once=True))  # no exception
    with pytest.raises(PolicyViolation) as exc:
        ensure_view_once_allowed(BuiltinPolicy(allow_view_once=False))
    assert exc.value.code == "view_once_disabled"


def test_policy_violation_maps_to_http_403_with_code():
    resp = api_exception_handler(PolicyViolation("view_once_disabled", "nope"), {})
    assert resp.status_code == 403 and resp.data == {"detail": "nope", "code": "view_once_disabled"}


def test_device_trust_flag():
    assert device_trust_required(BuiltinPolicy(require_device_trust=True)) is True
    assert device_trust_required(BuiltinPolicy()) is False


# --- effective policy resolution ----------------------------------------------------------

def test_effective_policy_is_the_active_one(org_a):
    set_policy(org_a, min_length=22)
    p = get_effective_policy(org_a.id)
    assert p.min_length == 22 and p.source == "organization"


def test_effective_policy_falls_back_to_safe_builtin_defaults(org_a):
    SecurityPolicy.objects.filter(organization=org_a).delete()
    p = get_effective_policy(org_a.id)
    assert p.source == "builtin_default" and p.min_length == 12 and p.require_symbols is True
    assert get_effective_policy(None).source == "builtin_default"


def test_policy_changes_apply_immediately_with_no_stale_cache(org_a):
    assert get_effective_policy(org_a.id).min_length == 12
    set_policy(org_a, min_length=40)
    assert get_effective_policy(org_a.id).min_length == 40


# --- live enforcement through Django's password validation ---------------------------------

def test_account_password_validation_uses_the_users_organization_policy(make_user, org_a, org_b):
    set_policy(org_a, min_length=20)
    set_policy(org_b, min_length=8, require_symbols=False)
    user_a, user_b = make_user(org_a), make_user(org_b)
    candidate = "Plainpassw0rd"  # 13 chars, no symbol
    with pytest.raises(ValidationError) as exc:
        validate_password(candidate, user_a)
    assert any("20 characters" in m for m in exc.value.messages)
    validate_password(candidate, user_b)  # org B's relaxed policy accepts it; org A's does not leak over


def test_validation_without_a_user_uses_builtin_defaults():
    with pytest.raises(ValidationError):
        validate_password("short")
    validate_password("A-reasonably-long-pass!")


def test_symbol_requirement_is_enforced_server_side(make_user, org_a):
    user = make_user(org_a)
    with pytest.raises(ValidationError) as exc:
        validate_password("NoSymbolsInThisOneAtAll1", user)
    assert any("symbol" in m for m in exc.value.messages)
