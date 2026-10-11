from dataclasses import dataclass
from datetime import timedelta

import pytest
from django.utils import timezone

from apps.lockdown.models import LockdownState
from apps.sharing.models import Share
from apps.vault.models import Credential
from apps.vault.tests.conftest import GOOD, GOOD2, db_dump, plaintext_in, set_policy  # noqa: F401  (re-exported fixtures)

CRED_URL = "/api/vault/credentials/"


@dataclass
class Cred:
    id: int
    uid: str


@pytest.fixture
def owner(make_user, org_a):
    return make_user(org_a, "EMPLOYEE", email="owner@org-a.example")


@pytest.fixture
def owner_client(api_as, owner):
    return api_as(owner)


@pytest.fixture
def bob(make_user, org_a):
    return make_user(org_a, "EMPLOYEE", email="bob@org-a.example")


@pytest.fixture
def carol(make_user, org_a):
    return make_user(org_a, "EMPLOYEE", email="carol@org-a.example")


@pytest.fixture
def dave(make_user, org_a):
    return make_user(org_a, "EMPLOYEE", email="dave@org-a.example")


@pytest.fixture
def cred(owner_client):
    body = owner_client.post(CRED_URL, {"title": "Prod DB", "username": "svc", "password": GOOD}, format="json").json()
    return Cred(id=body["id"], uid=Credential.objects.get(pk=body["id"]).uid)


def share_url(cid):
    return f"{CRED_URL}{cid}/shares/"


def do_share(client, cid, grantee, **kw):
    return client.post(share_url(cid), {"grantee_email": grantee.email, **kw}, format="json")


def do_reveal(client, cid):
    return client.post(f"{CRED_URL}{cid}/reveal/")


def in_hours(n):
    return (timezone.now() + timedelta(hours=n)).isoformat()


def lock(org, initiator, scope="GLOBAL", target=None, active=True):
    return LockdownState.objects.create(
        organization=org, scope=scope, target_user=target, initiator=initiator, reason="incident drill", is_active=active
    )


def unlock(state):
    state.is_active = False
    state.resolved_at = timezone.now()
    state.save()


def grant_row(cid, grantee):
    return Share.objects.filter(credential_id=cid, grantee=grantee).order_by("-id").first()
