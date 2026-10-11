import itertools

import pytest
from rest_framework.test import APIClient

from apps.accounts.models import AccountStatus, User
from apps.accounts.rbac import assign_role, create_organization

PASSWORD = "Correct-Horse-Battery-9"
_seq = itertools.count(1)


@pytest.fixture
def org_a(db):
    return create_organization("Org A", "org-a")


@pytest.fixture
def org_b(db):
    return create_organization("Org B", "org-b")


@pytest.fixture
def make_user(db):
    def _make(org, role=None, email=None, status=AccountStatus.ACTIVE, **extra):
        n = next(_seq)
        user = User.objects.create_user(
            email or f"user{n}@{org.slug}.example", PASSWORD, organization=org, full_name=f"User {n}", status=status, **extra
        )
        if role:
            assign_role(user, role)
        return user

    return _make


@pytest.fixture
def api():
    return APIClient()


@pytest.fixture
def api_as(make_user):
    """api_as(user) -> APIClient logged in through a real server-side session."""

    def _client(user):
        c = APIClient()
        c.force_login(user)
        return c

    return _client
