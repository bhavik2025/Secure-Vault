import pytest
from django.db import connection

from apps.policies.models import SecurityPolicy

GOOD = "Zx9#kLm2$Qw8!"  # satisfies the default policy (>= 12 chars, has a symbol)
GOOD2 = "Rt4%nBv7&Hc3?"


@pytest.fixture
def emp(make_user, org_a):
    return make_user(org_a, "EMPLOYEE")


@pytest.fixture
def emp_client(api_as, emp):
    return api_as(emp)


@pytest.fixture
def set_policy(org_a):
    def _set(**fields):
        SecurityPolicy.objects.filter(organization=org_a, is_active=True).update(**fields)

    return _set


@pytest.fixture
def db_dump():
    """Text of every row of every table (bytea shown as hex), for 'is plaintext stored anywhere?' checks."""

    def _dump() -> str:
        parts = []
        with connection.cursor() as cur:
            cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'")
            for (table,) in cur.fetchall():
                cur.execute(f'SELECT t::text FROM "{table}" t')
                parts.extend(row[0] for row in cur.fetchall())
        return "\n".join(parts)

    return _dump


def plaintext_in(secret: str, haystack: str) -> bool:
    """True if the secret appears in text, as hex (bytea), or percent/JSON-escaped forms."""
    return secret in haystack or secret.encode().hex() in haystack.lower()
