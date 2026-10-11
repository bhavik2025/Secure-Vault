from datetime import timedelta

import pytest
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.notifications.models import Notification
from apps.organizations.models import Department
from apps.sharing.models import AccessRequest, Share

from .conftest import CRED_URL, GOOD, do_reveal, do_share, lock, unlock

pytestmark = pytest.mark.django_db
URL = "/api/vault/access-requests/"
REASON = "Need to rotate the production database credentials"


def ask(client, cred, **over):
    body = {"credential_uid": str(cred.uid), "reason": REASON, "requested_hours": 4, **over}
    return client.post(URL, body, format="json")


@pytest.fixture
def dept(org_a):
    return Department.objects.create(organization=org_a, name="Engineering", code="ENG")


@pytest.fixture
def manager(make_user, org_a, dept):
    return make_user(org_a, "DEPARTMENT_MANAGER", department=dept)


# --- creating requests --------------------------------------------------------------------------------------

def test_request_is_created_pending_audited_and_the_owner_is_notified(api_as, bob, owner, cred):
    resp = ask(api_as(bob), cred)
    body = resp.json()
    assert resp.status_code == 201 and body["status"] == "PENDING" and body["credential_title"] == "Prod DB"
    assert body["requester"]["id"] == bob.pk and body["requested_hours"] == 4 and body["can_decide"] is False
    ev = AuditEvent.objects.get(action="ACCESS_REQUEST")
    assert ev.actor_id == bob.pk and ev.metadata["hours"] == 4 and REASON not in str(ev.metadata)
    note = Notification.objects.get(recipient=owner)
    assert note.type == "ACCESS_REQUESTED" and note.priority == "HIGH" and GOOD not in note.message


@pytest.mark.parametrize(
    "over", [{"reason": "too short"}, {"requested_hours": 0}, {"requested_hours": 169}, {"credential_uid": "not-a-uuid"}]
)
def test_invalid_requests_are_rejected(api_as, bob, cred, over):
    assert ask(api_as(bob), cred, **over).status_code == 400


def test_unknown_foreign_and_archived_credentials_all_return_404(api_as, make_user, org_b, owner_client, bob, cred):
    import uuid

    assert ask(api_as(bob), type("C", (), {"uid": uuid.uuid4()})).status_code == 404
    assert ask(api_as(make_user(org_b, "EMPLOYEE")), cred).status_code == 404
    owner_client.post(f"{CRED_URL}{cred.id}/archive/")
    assert ask(api_as(bob), cred).status_code == 404


def test_owner_cannot_request_their_own_credential(owner_client, cred):
    r = ask(owner_client, cred)
    assert r.status_code == 400 and r.json()["code"] == "own_credential"


def test_cannot_request_access_you_already_have_or_a_second_pending_request(owner_client, api_as, bob, cred):
    b = api_as(bob)
    assert ask(b, cred).status_code == 201
    assert ask(b, cred).status_code == 409  # one pending request at a time
    do_share(owner_client, cred.id, bob)
    other = AccessRequest.objects.get().pk
    b.post(f"{URL}{other}/cancel/")
    assert ask(b, cred).status_code == 409  # already has view access
    assert ask(b, cred, want_edit=True).status_code == 201  # but may ask for more (edit)


# --- deciding ------------------------------------------------------------------------------------------------------

def test_owner_approves_and_a_time_bound_grant_is_created_for_the_requester(owner_client, api_as, owner, bob, cred):
    rid = ask(api_as(bob), cred, requested_hours=4).json()["id"]
    assert owner_client.get(f"{URL}?scope=review").json()["results"][0]["can_decide"] is True
    resp = owner_client.post(f"{URL}{rid}/approve/", {"note": "ok"}, format="json")
    body = resp.json()
    assert resp.status_code == 200 and body["status"] == "APPROVED" and body["decided_by"]["id"] == owner.pk
    share = Share.objects.get(pk=body["resulting_share"])
    assert (share.grantor_id, share.grantee_id) == (owner.pk, bob.pk)
    assert (share.can_view, share.can_edit, share.can_share, share.is_view_once) == (True, False, False, False)
    lease = share.expires_at - timezone.now()
    assert timedelta(hours=3, minutes=55) < lease <= timedelta(hours=4)
    assert do_reveal(api_as(bob), cred.id).json()["password"] == GOOD
    assert Notification.objects.filter(recipient=bob, type="ACCESS_APPROVED").exists()
    ev = AuditEvent.objects.get(action="ACCESS_DECISION")
    assert ev.reason_code == "approved" and ev.metadata["decided_by_owner"] is True
    assert AuditEvent.objects.filter(action="SHARE", reason_code="direct").count() == 1


def test_approver_can_shorten_but_never_extend_the_lease(owner_client, api_as, bob, carol, cred):
    short = ask(api_as(bob), cred, requested_hours=10).json()["id"]
    long_ = ask(api_as(carol), cred, requested_hours=2).json()["id"]
    s1 = Share.objects.get(pk=owner_client.post(f"{URL}{short}/approve/", {"hours": 1}, format="json").json()["resulting_share"])
    s2 = Share.objects.get(pk=owner_client.post(f"{URL}{long_}/approve/", {"hours": 100}, format="json").json()["resulting_share"])
    assert s1.expires_at - timezone.now() <= timedelta(hours=1)
    assert s2.expires_at - timezone.now() <= timedelta(hours=2)


def test_edit_request_yields_an_edit_grant_and_share_is_never_requestable(owner_client, api_as, bob, cred):
    rid = ask(api_as(bob), cred, want_edit=True).json()["id"]
    share = Share.objects.get(pk=owner_client.post(f"{URL}{rid}/approve/").json()["resulting_share"])
    assert share.can_edit is True and share.can_share is False


def test_rejection_creates_no_grant(owner_client, api_as, bob, cred):
    rid = ask(api_as(bob), cred).json()["id"]
    body = owner_client.post(f"{URL}{rid}/reject/", {"note": "not needed"}, format="json").json()
    assert body["status"] == "REJECTED" and body["resulting_share"] is None
    assert not Share.objects.exists() and do_reveal(api_as(bob), cred.id).status_code == 404
    assert Notification.objects.filter(recipient=bob, type="ACCESS_REJECTED").exists()


def test_a_decision_is_final(owner_client, api_as, bob, cred):
    rid = ask(api_as(bob), cred).json()["id"]
    owner_client.post(f"{URL}{rid}/approve/")
    assert owner_client.post(f"{URL}{rid}/approve/").status_code == 409
    assert owner_client.post(f"{URL}{rid}/reject/").status_code == 409
    assert api_as(bob).post(f"{URL}{rid}/cancel/").status_code == 409
    assert Share.objects.count() == 1


def test_requester_can_cancel_only_their_own_pending_request(owner_client, api_as, bob, carol, cred):
    rid = ask(api_as(bob), cred).json()["id"]
    assert api_as(carol).post(f"{URL}{rid}/cancel/").status_code == 404
    assert owner_client.post(f"{URL}{rid}/cancel/").status_code == 404
    assert api_as(bob).post(f"{URL}{rid}/cancel/").json()["status"] == "CANCELLED"
    assert owner_client.post(f"{URL}{rid}/approve/").status_code == 409


def test_only_authorized_people_can_decide(owner_client, api_as, bob, carol, dave, cred):
    rid = ask(api_as(bob), cred).json()["id"]
    assert api_as(carol).post(f"{URL}{rid}/approve/").status_code == 404  # unrelated colleague
    assert api_as(bob).post(f"{URL}{rid}/approve/").status_code == 404  # nobody approves their own request
    assert api_as(carol).get(f"{URL}{rid}/").status_code == 404
    assert not Share.objects.exists()


# --- department managers ----------------------------------------------------------------------------------------------

def test_manager_in_the_owners_department_can_approve_but_the_owner_remains_the_grantor(
    api_as, make_user, org_a, dept, manager, owner, bob, cred
):
    owner.department = dept
    owner.save()
    rid = ask(api_as(bob), cred).json()["id"]
    assert Notification.objects.filter(recipient=manager, type="ACCESS_REQUESTED").exists()
    assert api_as(manager).get(f"{URL}?scope=review").json()["count"] == 1
    body = api_as(manager).post(f"{URL}{rid}/approve/").json()
    share = Share.objects.get(pk=body["resulting_share"])
    assert share.grantor_id == owner.pk  # a manager authorizes; only an owner can hand out the secret
    assert AuditEvent.objects.get(action="ACCESS_DECISION").metadata["decided_by_owner"] is False
    assert AuditEvent.objects.get(action="ACCESS_DECISION").actor_id == manager.pk
    assert do_reveal(api_as(bob), cred.id).status_code == 200


def test_manager_outside_the_owners_department_or_without_the_permission_cannot_decide(
    api_as, make_user, org_a, dept, owner, bob, cred
):
    owner.department = dept
    owner.save()
    other_dept = Department.objects.create(organization=org_a, name="Finance", code="FIN")
    elsewhere = make_user(org_a, "DEPARTMENT_MANAGER", department=other_dept)
    employee_same_dept = make_user(org_a, "EMPLOYEE", department=dept)  # lacks requests.approve
    rid = ask(api_as(bob), cred).json()["id"]
    for who in (elsewhere, employee_same_dept):
        assert api_as(who).post(f"{URL}{rid}/approve/").status_code == 404
        assert api_as(who).get(f"{URL}?scope=review").json()["count"] == 0
    assert not Share.objects.exists()


def test_a_manager_cannot_approve_their_own_request(api_as, owner, dept, manager, cred):
    owner.department = dept
    owner.save()
    rid = ask(api_as(manager), cred).json()["id"]
    assert api_as(manager).post(f"{URL}{rid}/approve/").status_code == 404


def test_other_tenants_managers_see_nothing(api_as, make_user, org_b, bob, cred):
    ask(api_as(bob), cred)
    outsider = make_user(org_b, "DEPARTMENT_MANAGER")
    assert api_as(outsider).get(f"{URL}?scope=review").json()["count"] == 0


# --- staleness, lockdown, listings ------------------------------------------------------------------------------------------

def test_stale_pending_requests_expire_and_cannot_be_approved_but_do_not_block_new_ones(owner_client, api_as, bob, cred):
    rid = ask(api_as(bob), cred).json()["id"]
    AccessRequest.objects.filter(pk=rid).update(created_at=timezone.now() - timedelta(days=8))
    assert api_as(bob).get(f"{URL}{rid}/").json()["status"] == "EXPIRED"
    assert owner_client.post(f"{URL}{rid}/approve/").status_code == 409
    assert ask(api_as(bob), cred).status_code == 201


def test_lockdown_blocks_new_requests_and_approvals(owner_client, api_as, owner, bob, cred):
    rid = ask(api_as(bob), cred).json()["id"]
    state = lock(owner.organization, owner)
    assert owner_client.post(f"{URL}{rid}/approve/").status_code == 423
    assert ask(api_as(bob), cred, requested_hours=2).status_code == 423
    assert not Share.objects.exists()
    unlock(state)
    assert owner_client.post(f"{URL}{rid}/approve/").status_code == 200


def test_listing_scopes_and_filters(owner_client, api_as, bob, carol, cred):
    ask(api_as(bob), cred)
    ask(api_as(carol), cred)
    assert api_as(bob).get(URL).json()["count"] == 1
    assert owner_client.get(URL).json()["count"] == 0  # "mine" = requests I made
    assert owner_client.get(f"{URL}?scope=review").json()["count"] == 2
    assert owner_client.get(f"{URL}?scope=review&status=APPROVED").json()["count"] == 0
    assert api_as(bob).get(f"{URL}?scope=review").json()["count"] == 0


def test_approved_access_can_be_revoked_like_any_other_grant(owner_client, api_as, bob, cred):
    rid = ask(api_as(bob), cred).json()["id"]
    sid = owner_client.post(f"{URL}{rid}/approve/").json()["resulting_share"]
    owner_client.post(f"/api/vault/shares/{sid}/revoke/")
    assert do_reveal(api_as(bob), cred.id).json()["code"] == "grant_revoked"


def test_request_endpoints_require_authentication(api):
    assert api.get(URL).status_code == 403
    assert api.post(URL, {}, format="json").status_code == 403
