import pytest
from django.db import IntegrityError, transaction

from apps.audit.models import AuditEvent
from apps.lockdown.gate import active_lockdown, lockdown_gate
from apps.core.api_errors import LockdownActive
from apps.lockdown.models import LockdownState
from apps.sharing.tests.conftest import lock, unlock

pytestmark = pytest.mark.django_db
CREDS = "/api/vault/credentials/"
GOOD = "Zx9#kLm2$Qw8!"


def test_global_user_and_resolved_scopes(make_user, org_a, org_b):
    admin, alice, bob = (make_user(org_a, "PLATFORM_ADMIN"), make_user(org_a), make_user(org_a))
    outsider = make_user(org_b)
    assert active_lockdown(alice) is None

    user_lock = lock(org_a, admin, scope="USER", target=alice)
    assert active_lockdown(alice) == user_lock and active_lockdown(bob) is None

    global_lock = lock(org_a, admin)
    assert active_lockdown(bob) == global_lock and active_lockdown(outsider) is None
    with pytest.raises(LockdownActive):
        lockdown_gate(bob)

    unlock(global_lock)
    unlock(user_lock)
    assert active_lockdown(alice) is None and active_lockdown(bob) is None
    lockdown_gate(alice)  # no exception


def test_database_requires_a_target_for_user_scope_and_forbids_one_for_global(make_user, org_a):
    admin, alice = make_user(org_a, "PLATFORM_ADMIN"), make_user(org_a)
    with pytest.raises(IntegrityError), transaction.atomic():
        LockdownState.objects.create(organization=org_a, scope="USER", initiator=admin, reason="x")
    with pytest.raises(IntegrityError), transaction.atomic():
        LockdownState.objects.create(organization=org_a, scope="GLOBAL", target_user=alice, initiator=admin, reason="x")


def test_writing_secrets_is_blocked_during_lockdown_but_reading_metadata_and_archiving_are_not(api_as, make_user, org_a):
    me, admin = make_user(org_a, "EMPLOYEE"), make_user(org_a, "PLATFORM_ADMIN")
    c = api_as(me)
    cid = c.post(CREDS, {"title": "Before", "password": GOOD}, format="json").json()["id"]
    state = lock(org_a, admin)

    blocked = [
        c.post(CREDS, {"title": "During", "password": GOOD}, format="json"),
        c.patch(f"{CREDS}{cid}/", {"password": "Nw8&vKd3!pQz"}, format="json"),
        c.post("/api/vault/notes/", {"title": "Note", "content": "x"}, format="json"),
    ]
    assert [r.status_code for r in blocked] == [423, 423, 423]
    assert all(r.json()["code"] == "lockdown_active" for r in blocked)
    assert c.get(CREDS).status_code == 200 and c.get(f"{CREDS}{cid}/").status_code == 200  # masked metadata only
    assert c.post(f"{CREDS}{cid}/archive/").status_code == 200

    denied = AuditEvent.objects.filter(action="AUTHZ_DENIED", reason_code="lockdown_active")
    assert denied.count() == 3 and all(e.actor_id == me.pk for e in denied)
    unlock(state)
    assert c.post(CREDS, {"title": "After", "password": GOOD}, format="json").status_code == 201


def test_a_user_scoped_lockdown_does_not_stop_colleagues(api_as, make_user, org_a):
    admin, locked, free = make_user(org_a, "PLATFORM_ADMIN"), make_user(org_a, "EMPLOYEE"), make_user(org_a, "EMPLOYEE")
    lock(org_a, admin, scope="USER", target=locked)
    assert api_as(locked).post(CREDS, {"title": "Nope", "password": GOOD}, format="json").status_code == 423
    assert api_as(free).post(CREDS, {"title": "Fine", "password": GOOD}, format="json").status_code == 201
