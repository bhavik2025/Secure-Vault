import threading

import pytest
from django.db import connections
from rest_framework.test import APIClient

from apps.audit.models import AuditEvent
from apps.sharing.models import Share
from apps.vault.models import Credential

from .conftest import CRED_URL, GOOD, do_reveal, do_share, grant_row, lock, unlock

pytestmark = pytest.mark.django_db


def view_once(owner_client, cid, who, **kw):
    r = do_share(owner_client, cid, who, is_view_once=True, **kw)
    assert r.status_code == 201, r.json()
    return r.json()["id"]


# --- creation rules ---------------------------------------------------------------------------------------

def test_view_once_grants_are_view_only(owner_client, bob, cred):
    for extra in ({"can_edit": True}, {"can_share": True}, {"can_view": False, "can_edit": True}):
        r = do_share(owner_client, cred.id, bob, is_view_once=True, **extra)
        assert r.status_code == 400 and r.json()["code"] == "view_once_view_only"
    assert not Share.objects.exists()


def test_policy_can_forbid_view_once_sharing(owner_client, bob, cred, set_policy):
    set_policy(allow_view_once=False)
    r = do_share(owner_client, cred.id, bob, is_view_once=True)
    assert r.status_code == 403 and r.json()["code"] == "view_once_disabled"
    assert do_share(owner_client, cred.id, bob).status_code == 201  # ordinary sharing is unaffected


def test_a_view_once_recipient_cannot_share_it_onward(owner_client, api_as, bob, carol, cred):
    view_once(owner_client, cred.id, bob)
    r = do_share(api_as(bob), cred.id, carol)
    assert r.status_code == 403 and r.json()["code"] == "share_not_granted"


# --- consumption ------------------------------------------------------------------------------------------------

def test_first_reveal_succeeds_and_every_later_attempt_is_410(owner_client, api_as, bob, cred):
    sid = view_once(owner_client, cred.id, bob)
    b = api_as(bob)
    first = do_reveal(b, cred.id)
    assert first.status_code == 200 and first.json()["password"] == GOOD and first.json()["view_once"] is True
    for _ in range(3):
        again = do_reveal(b, cred.id)
        assert again.status_code == 410 and again.json()["code"] == "grant_consumed" and GOOD not in again.content.decode()
    share = Share.objects.get(pk=sid)
    assert share.burned_at is not None and share.status_at() == "CONSUMED"
    assert AuditEvent.objects.filter(action="REVEAL", outcome="SUCCESS").count() == 1
    assert AuditEvent.objects.filter(action="REVEAL", reason_code="grant_consumed").count() == 3


def test_consumed_grant_stops_everything_else_too(owner_client, api_as, bob, cred):
    view_once(owner_client, cred.id, bob)
    b = api_as(bob)
    do_reveal(b, cred.id)
    assert b.get(f"{CRED_URL}{cred.id}/").status_code == 410
    assert b.get("/api/vault/shared-with-me/").json()["results"] == []
    listed = owner_client.get(f"{CRED_URL}{cred.id}/shares/").json()["results"][0]
    assert listed["status"] == "CONSUMED" and listed["burned_at"]


def test_the_owner_is_never_affected_by_a_view_once_grant(owner_client, bob, cred):
    view_once(owner_client, cred.id, bob)
    assert do_reveal(owner_client, cred.id).json()["view_once"] is False
    assert do_reveal(owner_client, cred.id).status_code == 200


def test_a_reusable_grant_is_used_in_preference_to_spending_a_one_time_grant(owner_client, api_as, bob, carol, cred):
    do_share(owner_client, cred.id, carol, can_share=True)
    do_share(owner_client, cred.id, bob)  # normal grant from the owner
    do_share(api_as(carol), cred.id, bob, is_view_once=True)  # plus a one-time grant from carol
    b = api_as(bob)
    for _ in range(3):
        assert do_reveal(b, cred.id).json()["view_once"] is False
    assert Share.objects.get(grantor=carol, grantee=bob).burned_at is None  # still unspent


# --- failed authorization never burns ------------------------------------------------------------------------------

def test_lockdown_refusal_does_not_consume_the_grant(owner_client, api_as, owner, bob, cred):
    sid = view_once(owner_client, cred.id, bob)
    state = lock(owner.organization, owner)
    b = api_as(bob)
    assert do_reveal(b, cred.id).status_code == 423
    assert Share.objects.get(pk=sid).burned_at is None
    unlock(state)
    assert do_reveal(b, cred.id).status_code == 200  # the one chance was still there
    assert do_reveal(b, cred.id).status_code == 410


def test_device_policy_refusal_does_not_consume_the_grant(owner_client, api_as, bob, cred, set_policy):
    sid = view_once(owner_client, cred.id, bob)
    set_policy(require_device_trust=True)
    assert do_reveal(api_as(bob), cred.id).status_code == 403
    assert Share.objects.get(pk=sid).burned_at is None
    set_policy(require_device_trust=False)
    assert do_reveal(api_as(bob), cred.id).status_code == 200


def test_wrong_people_cannot_burn_someone_elses_grant(owner_client, api_as, bob, carol, cred):
    sid = view_once(owner_client, cred.id, bob)
    for _ in range(3):
        assert do_reveal(api_as(carol), cred.id).status_code == 404
    assert Share.objects.get(pk=sid).burned_at is None
    assert do_reveal(api_as(bob), cred.id).status_code == 200


def test_expired_and_revoked_one_time_grants_are_refused_without_burning(owner_client, api_as, bob, carol, cred):
    from datetime import timedelta

    from django.utils import timezone

    expired = view_once(owner_client, cred.id, bob, expires_in_hours=1)
    revoked = view_once(owner_client, cred.id, carol)
    Share.objects.filter(pk=expired).update(expires_at=timezone.now() - timedelta(seconds=1))
    owner_client.post(f"/api/vault/shares/{revoked}/revoke/")
    assert do_reveal(api_as(bob), cred.id).json()["code"] == "grant_expired"
    assert do_reveal(api_as(carol), cred.id).json()["code"] == "grant_revoked"
    assert Share.objects.filter(burned_at__isnull=False).count() == 0


def test_a_decryption_failure_rolls_back_and_leaves_the_grant_unspent(owner_client, api_as, bob, cred):
    sid = view_once(owner_client, cred.id, bob)
    good = bytes(Credential.objects.get(pk=cred.id).password_enc)
    bad = bytearray(good)
    bad[-1] ^= 0xFF
    Credential.objects.filter(pk=cred.id).update(password_enc=bytes(bad))
    assert do_reveal(api_as(bob), cred.id).status_code == 500
    assert Share.objects.get(pk=sid).burned_at is None  # the burn is in the same transaction as the decrypt
    Credential.objects.filter(pk=cred.id).update(password_enc=good)
    assert do_reveal(api_as(bob), cred.id).status_code == 200


def test_archived_credential_does_not_burn(owner_client, api_as, bob, cred):
    sid = view_once(owner_client, cred.id, bob)
    owner_client.post(f"{CRED_URL}{cred.id}/archive/")
    assert do_reveal(api_as(bob), cred.id).status_code == 404
    assert Share.objects.get(pk=sid).burned_at is None


# --- concurrency ------------------------------------------------------------------------------------------------------

@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("round_", range(3))
def test_concurrent_reveals_of_one_view_once_grant_succeed_exactly_once(owner_client, bob, cred, round_):
    sid = view_once(owner_client, cred.id, bob)
    n = 8
    clients = []
    for _ in range(n):
        c = APIClient()
        c.force_login(bob)
        clients.append(c)
    barrier = threading.Barrier(n)
    results, errors = [], []

    def worker(client):
        try:
            barrier.wait(timeout=10)
            r = do_reveal(client, cred.id)
            results.append((r.status_code, r.json().get("code"), "password" in r.json()))
        except Exception as exc:  # pragma: no cover
            errors.append(exc)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=worker, args=(c,)) for c in clients]
    [t.start() for t in threads]
    [t.join() for t in threads]

    assert not errors, errors
    assert sorted(code for code, _, _ in results) == [200] + [410] * (n - 1)
    assert sum(1 for _, _, leaked in results if leaked) == 1  # exactly ONE response carried the secret
    assert Share.objects.get(pk=sid).burned_at is not None
    assert AuditEvent.objects.filter(action="REVEAL", outcome="SUCCESS").count() == 1
    assert AuditEvent.objects.filter(action="REVEAL", reason_code="grant_consumed").count() == n - 1


@pytest.mark.django_db(transaction=True)
def test_concurrent_identical_shares_create_exactly_one_grant(owner_client, owner, bob, cred):
    from apps.sharing.tests.conftest import share_url

    n = 6
    clients = []
    for _ in range(n):
        c = APIClient()
        c.force_login(owner)
        clients.append(c)
    barrier = threading.Barrier(n)
    codes = []

    def worker(client):
        barrier.wait(timeout=10)
        codes.append(client.post(share_url(cred.id), {"grantee_email": bob.email}, format="json").status_code)
        connections.close_all()

    threads = [threading.Thread(target=worker, args=(c,)) for c in clients]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(codes) == [201] + [409] * (n - 1)
    assert Share.objects.filter(credential_id=cred.id, grantee=bob).count() == 1


@pytest.mark.django_db(transaction=True)
def test_revocation_racing_with_delegation_never_leaves_a_usable_child(owner_client, owner, api_as, bob, carol, cred):
    """A child attached concurrently with a revoke of its parent must end up revoked, not orphaned-and-live."""
    do_share(owner_client, cred.id, bob, can_share=True)
    parent = grant_row(cred.id, bob)
    bob_client, owner_c = APIClient(), APIClient()
    bob_client.force_login(bob)
    owner_c.force_login(owner)
    barrier = threading.Barrier(2)

    def delegate():
        barrier.wait(timeout=10)
        do_share(bob_client, cred.id, carol)
        connections.close_all()

    def revoke():
        barrier.wait(timeout=10)
        owner_c.post(f"/api/vault/shares/{parent.pk}/revoke/")
        connections.close_all()

    ts = [threading.Thread(target=delegate), threading.Thread(target=revoke)]
    [t.start() for t in ts]
    [t.join() for t in ts]

    carol_client = APIClient()
    carol_client.force_login(carol)
    # Whatever the interleaving, carol must not be able to use access derived from a revoked parent.
    assert do_reveal(carol_client, cred.id).status_code in (403, 404)
    assert not Share.objects.filter(grantee=carol, revoked_at__isnull=True, parent__revoked_at__isnull=False).exists()
