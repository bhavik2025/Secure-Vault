import pytest
from django.db import IntegrityError, transaction

from apps.audit.models import AuditEvent
from apps.notifications.models import Notification
from apps.sharing.models import Share

from .conftest import CRED_URL, Cred, do_reveal, do_share, grant_row, in_hours, lock, share_url, GOOD

pytestmark = pytest.mark.django_db


# --- direct sharing -------------------------------------------------------------------------------

def test_owner_shares_directly_and_everything_is_recorded(owner_client, owner, bob, cred):
    resp = do_share(owner_client, cred.id, bob, can_edit=True, expires_in_hours=24)
    body = resp.json()
    assert resp.status_code == 201
    assert (body["can_view"], body["can_edit"], body["can_share"], body["status"]) == (True, True, False, "ACTIVE")
    assert body["grantor"]["id"] == owner.pk and body["grantee"]["id"] == bob.pk and body["parent"] is None and body["depth"] == 1
    ev = AuditEvent.objects.get(action="SHARE")
    assert ev.actor_id == owner.pk and ev.target_id == str(cred.id) and ev.reason_code == "direct"
    assert ev.metadata["grantee_id"] == bob.pk and ev.metadata["edit"] is True
    note = Notification.objects.get(recipient=bob)
    assert note.type == "SHARE_RECEIVED" and "Prod DB" in note.message and GOOD not in note.message


def test_grantee_sees_masked_metadata_but_no_secret_and_no_owner_internals(owner_client, api_as, bob, cred):
    do_share(owner_client, cred.id, bob)
    resp = api_as(bob).get(f"{CRED_URL}{cred.id}/")
    body = resp.json()
    assert resp.status_code == 200 and body["access"]["role"] == "shared" and body["access"]["can_view"] is True
    assert "password" not in body and GOOD not in resp.content.decode()
    assert body["reused_in_my_vault"] is False  # a delegate learns nothing about the owner's other credentials
    assert body["request_code"] is None  # only the owner hands out the access-request identifier


def test_expiry_and_permission_validation(owner_client, bob, cred):
    assert do_share(owner_client, cred.id, bob, expires_at=in_hours(-1)).json()["code"] == "expiry_in_past"
    assert do_share(owner_client, cred.id, bob, expires_at=in_hours(5), expires_in_hours=5).status_code == 400
    r = do_share(owner_client, cred.id, bob, can_view=False)
    assert r.status_code == 400 and r.json()["code"] == "no_permission"
    assert not Share.objects.exists()


def test_invalid_grantees_all_look_identical(owner_client, owner, make_user, org_b, cred):
    from apps.accounts.models import AccountStatus

    suspended = make_user(owner.organization, status=AccountStatus.SUSPENDED)
    foreign = make_user(org_b, "EMPLOYEE")
    bodies = []
    for email in ("nobody@org-a.example", suspended.email, foreign.email, owner.email):
        r = owner_client.post(share_url(cred.id), {"grantee_email": email}, format="json")
        assert r.status_code == 400
        bodies.append(r.json())
    assert all(b == bodies[0] and b["code"] == "invalid_grantee" for b in bodies)  # no account/tenant oracle


def test_duplicate_active_share_conflicts_until_revoked(owner_client, bob, cred):
    sid = do_share(owner_client, cred.id, bob).json()["id"]
    assert do_share(owner_client, cred.id, bob).status_code == 409
    owner_client.post(f"/api/vault/shares/{sid}/revoke/")
    assert do_share(owner_client, cred.id, bob).status_code == 201


def test_archived_credential_cannot_be_shared(owner_client, bob, cred):
    owner_client.post(f"{CRED_URL}{cred.id}/archive/")
    assert do_share(owner_client, cred.id, bob).status_code == 409


def test_strangers_and_other_tenants_get_404(api_as, bob, owner_client, make_user, org_b, cred):
    assert do_share(api_as(bob), cred.id, make_user(bob.organization, "EMPLOYEE")).status_code == 404
    assert api_as(make_user(org_b, "PLATFORM_ADMIN")).get(share_url(cred.id)).status_code == 404
    assert api_as(bob).get(share_url(cred.id)).status_code == 404


# --- EDIT and SHARE are independent -----------------------------------------------------------------

def test_edit_without_share_and_share_without_edit(owner_client, api_as, bob, carol, dave, cred):
    do_share(owner_client, cred.id, bob, can_view=False, can_edit=True)  # edit only
    do_share(owner_client, cred.id, carol, can_view=False, can_share=True)  # share only
    b, c = api_as(bob), api_as(carol)

    assert b.patch(f"{CRED_URL}{cred.id}/", {"title": "Edited by Bob"}, format="json").status_code == 200
    r = do_share(b, cred.id, dave)
    assert r.status_code == 403 and r.json()["code"] == "share_not_granted"
    assert do_reveal(b, cred.id).json()["code"] == "view_not_granted"  # EDIT does not imply VIEW

    r = c.patch(f"{CRED_URL}{cred.id}/", {"title": "Nope"}, format="json")
    assert r.status_code == 403 and r.json()["code"] == "edit_not_granted"
    assert do_share(c, cred.id, dave, can_view=False, can_share=True).status_code == 201
    assert do_share(c, cred.id, dave, can_view=True).status_code in (400, 409)  # cannot hand out VIEW it never had


def test_editor_can_rotate_password_and_owner_sees_the_new_secret(owner_client, api_as, bob, cred):
    do_share(owner_client, cred.id, bob, can_view=False, can_edit=True)
    assert api_as(bob).patch(f"{CRED_URL}{cred.id}/", {"password": "Nw8&vKd3!pQz"}, format="json").status_code == 200
    assert do_reveal(owner_client, cred.id).json()["password"] == "Nw8&vKd3!pQz"
    ev = AuditEvent.objects.filter(action="EDIT", target_type="credential").latest("id")
    assert ev.actor.email == bob.email and ev.metadata["rotated"] is True


def test_editor_cannot_archive(owner_client, api_as, bob, cred):
    do_share(owner_client, cred.id, bob, can_edit=True)
    assert api_as(bob).post(f"{CRED_URL}{cred.id}/archive/").status_code == 404  # archive is owner-only


def test_viewer_cannot_edit(owner_client, api_as, bob, cred):
    do_share(owner_client, cred.id, bob)
    r = api_as(bob).patch(f"{CRED_URL}{cred.id}/", {"title": "x1"}, format="json")
    assert r.status_code == 403 and r.json()["code"] == "edit_not_granted"


# --- delegation rules -----------------------------------------------------------------------------------

def test_delegate_cannot_exceed_upstream_permissions(owner_client, api_as, bob, carol, cred):
    do_share(owner_client, cred.id, bob, can_view=True, can_share=True)  # no EDIT
    b = api_as(bob)
    r = do_share(b, cred.id, carol, can_edit=True)
    assert r.status_code == 400 and r.json()["code"] == "exceeds_upstream_permissions"
    ok = do_share(b, cred.id, carol, can_view=True, can_share=True)
    assert ok.status_code == 201 and ok.json()["depth"] == 2 and ok.json()["parent"] == grant_row(cred.id, bob).pk
    assert AuditEvent.objects.filter(action="SHARE", reason_code="delegated").count() == 1


def test_delegate_cannot_outlive_the_upstream_share_and_inherits_its_expiry(owner_client, api_as, bob, carol, dave, cred):
    do_share(owner_client, cred.id, bob, can_share=True, expires_in_hours=10)
    b = api_as(bob)
    r = do_share(b, cred.id, carol, expires_in_hours=20)
    assert r.status_code == 400 and r.json()["code"] == "exceeds_upstream_lifetime"
    inherited = do_share(b, cred.id, carol)  # no expiry given -> capped at the parent's
    assert inherited.status_code == 201 and inherited.json()["expires_at"] == grant_row(cred.id, bob).expires_at.isoformat().replace("+00:00", "Z")
    assert do_share(b, cred.id, dave, expires_in_hours=5).status_code == 201


def test_unlimited_parent_allows_any_lifetime(owner_client, api_as, bob, carol, cred):
    do_share(owner_client, cred.id, bob, can_share=True)
    assert do_share(api_as(bob), cred.id, carol, expires_in_hours=1000).status_code == 201


def test_view_only_holder_cannot_delegate(owner_client, api_as, bob, carol, cred):
    do_share(owner_client, cred.id, bob)
    r = do_share(api_as(bob), cred.id, carol)
    assert r.status_code == 403 and r.json()["code"] == "share_not_granted"


def test_delegation_depth_is_limited(owner_client, api_as, make_user, org_a, cred):
    people = [make_user(org_a, "EMPLOYEE") for _ in range(6)]
    do_share(owner_client, cred.id, people[0], can_share=True)
    for upstream, nxt in zip(people, people[1:5]):
        assert do_share(api_as(upstream), cred.id, nxt, can_share=True).status_code == 201
    assert grant_row(cred.id, people[4]).depth == 5
    r = do_share(api_as(people[4]), cred.id, people[5])
    assert r.status_code == 400 and r.json()["code"] == "max_delegation_depth"


def test_cycles_and_sharing_back_to_the_owner_are_refused(owner_client, api_as, owner, bob, carol, cred):
    do_share(owner_client, cred.id, bob, can_share=True)
    do_share(api_as(bob), cred.id, carol, can_share=True)
    c = api_as(carol)
    for target in (bob, owner):
        r = do_share(c, cred.id, target)
        assert r.status_code == 400 and r.json()["code"] == "delegation_cycle"


def test_each_delegate_is_limited_by_their_own_grant_not_by_someone_elses(owner_client, api_as, bob, carol, dave, cred):
    do_share(owner_client, cred.id, bob, can_view=True, can_edit=True, can_share=True)
    do_share(owner_client, cred.id, carol, can_view=True, can_share=True)  # no EDIT
    assert do_share(api_as(carol), cred.id, dave, can_edit=True).json()["code"] == "exceeds_upstream_permissions"
    assert do_share(api_as(bob), cred.id, dave, can_edit=True).status_code == 201


# --- listings and tree ----------------------------------------------------------------------------------------

def test_listings_and_tree(owner_client, api_as, owner, bob, carol, cred):
    do_share(owner_client, cred.id, bob, can_share=True)
    do_share(api_as(bob), cred.id, carol)
    assert {r["grantee"]["email"] for r in owner_client.get(share_url(cred.id)).json()["results"]} == {bob.email, carol.email}
    assert [r["grantee"]["email"] for r in api_as(bob).get(share_url(cred.id)).json()["results"]] == [carol.email]
    assert api_as(carol).get(share_url(cred.id)).json()["results"] == []
    assert [r["credential_title"] for r in api_as(carol).get("/api/vault/shared-with-me/").json()["results"]] == ["Prod DB"]
    assert {r["grantee"]["email"] for r in owner_client.get("/api/vault/shared-by-me/").json()["results"]} == {bob.email}
    tree = owner_client.get(f"{share_url(cred.id)}tree/").json()["tree"]
    assert tree[0]["grantee"] == bob.email and tree[0]["children"][0]["grantee"] == carol.email
    assert api_as(bob).get(f"{share_url(cred.id)}tree/").status_code == 404  # owner only


# --- revocation ---------------------------------------------------------------------------------------------------------

def revoke(client, share_id):
    return client.post(f"/api/vault/shares/{share_id}/revoke/")


def build_chain(owner_client, api_as, cred, bob, carol, dave):
    do_share(owner_client, cred.id, bob, can_share=True)
    do_share(api_as(bob), cred.id, carol, can_share=True)
    do_share(api_as(carol), cred.id, dave)
    return grant_row(cred.id, bob), grant_row(cred.id, carol), grant_row(cred.id, dave)


def test_revoking_a_parent_invalidates_every_descendant_at_once(owner_client, api_as, bob, carol, dave, cred):
    g_bob, g_carol, g_dave = build_chain(owner_client, api_as, cred, bob, carol, dave)
    for who in (bob, carol, dave):
        assert do_reveal(api_as(who), cred.id).status_code == 200  # all three work beforehand

    resp = revoke(owner_client, g_bob.pk)
    assert resp.status_code == 200 and resp.json()["grants_revoked"] == 3 and resp.json()["status"] == "REVOKED"
    for g in (g_bob, g_carol, g_dave):
        g.refresh_from_db()
        assert g.revoked_at is not None
    assert g_bob.revoked_via_cascade is False and g_carol.revoked_via_cascade and g_dave.revoked_via_cascade

    for who in (bob, carol, dave):
        c = api_as(who)
        r = do_reveal(c, cred.id)
        assert r.status_code == 403 and r.json()["code"] == "grant_revoked"
        assert c.get(f"{CRED_URL}{cred.id}/").json()["code"] == "grant_revoked"
        assert c.get("/api/vault/shared-with-me/").json()["results"] == []
    ev = AuditEvent.objects.get(action="REVOKE")
    assert ev.reason_code == "cascade" and ev.metadata["grants_revoked"] == 3
    assert Notification.objects.filter(type="SHARE_REVOKED", priority="HIGH").count() == 3


def test_a_revoked_ancestor_alone_makes_descendants_unusable_even_if_cascade_marking_were_missing(owner_client, api_as, bob, carol, dave, cred):
    """Belt and braces: authorization walks the ancestor chain, so it does not trust the cascade flag alone."""
    from django.utils import timezone

    g_bob, g_carol, g_dave = build_chain(owner_client, api_as, cred, bob, carol, dave)
    Share.objects.filter(pk=g_bob.pk).update(revoked_at=timezone.now())  # parent only, no cascade
    for who in (carol, dave):
        r = do_reveal(api_as(who), cred.id)
        assert r.status_code == 403 and r.json()["code"] == "grant_revoked"


def test_an_expired_ancestor_makes_descendants_unusable(owner_client, api_as, bob, carol, dave, cred):
    from datetime import timedelta

    from django.utils import timezone

    _, g_carol, _ = build_chain(owner_client, api_as, cred, bob, carol, dave)
    Share.objects.filter(pk=grant_row(cred.id, bob).pk).update(expires_at=timezone.now() - timedelta(minutes=1))
    assert do_reveal(api_as(dave), cred.id).status_code == 403
    assert do_reveal(api_as(carol), cred.id).status_code == 403


def test_revoking_a_middle_grant_leaves_siblings_and_ancestors_working(owner_client, api_as, bob, carol, dave, cred, make_user, org_a):
    erin = make_user(org_a, "EMPLOYEE")
    g_bob, g_carol, g_dave = build_chain(owner_client, api_as, cred, bob, carol, dave)
    do_share(api_as(bob), cred.id, erin)  # sibling of carol under bob
    assert revoke(api_as(bob), g_carol.pk).json()["grants_revoked"] == 2  # carol + dave
    assert do_reveal(api_as(bob), cred.id).status_code == 200
    assert do_reveal(api_as(erin), cred.id).status_code == 200
    assert do_reveal(api_as(dave), cred.id).status_code == 403


def test_who_may_revoke(owner_client, api_as, bob, carol, dave, cred):
    g_bob, g_carol, _ = build_chain(owner_client, api_as, cred, bob, carol, dave)
    assert revoke(api_as(carol), g_carol.pk).status_code == 403  # the grantee cannot revoke their own grant
    assert revoke(api_as(dave), g_carol.pk).status_code == 404  # unrelated people can't even see it
    assert revoke(api_as(carol), g_bob.pk).status_code == 404
    assert revoke(api_as(bob), g_carol.pk).status_code == 200  # the grantor can
    assert revoke(api_as(bob), g_bob.pk).status_code == 403  # bob is the grantee of g_bob (owner issued it)
    assert revoke(owner_client, 999999).status_code == 404


def test_revoking_is_idempotent_and_audited_once(owner_client, bob, cred):
    sid = do_share(owner_client, cred.id, bob).json()["id"]
    assert revoke(owner_client, sid).json()["grants_revoked"] == 1
    assert revoke(owner_client, sid).json()["grants_revoked"] == 0
    assert AuditEvent.objects.filter(action="REVOKE").count() == 1


def test_revocation_works_during_a_lockdown_but_new_sharing_does_not(owner_client, owner, bob, carol, cred):
    sid = do_share(owner_client, cred.id, bob).json()["id"]
    lock(owner.organization, owner)
    r = do_share(owner_client, cred.id, carol)
    assert r.status_code == 423 and r.json()["code"] == "lockdown_active"
    assert revoke(owner_client, sid).status_code == 200  # containment must always be possible


def test_other_tenants_cannot_revoke(api_as, make_user, org_b, owner_client, bob, cred):
    sid = do_share(owner_client, cred.id, bob).json()["id"]
    assert revoke(api_as(make_user(org_b, "PLATFORM_ADMIN")), sid).status_code == 404


# --- database-level invariants ----------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "fields",
    [
        dict(can_view=False, can_edit=False, can_share=False),
        dict(is_view_once=True, can_edit=True),
        dict(is_view_once=True, can_share=True),
        dict(depth=6),
        dict(depth=0),
    ],
)
def test_database_rejects_invalid_grants(owner, bob, cred, fields):
    with pytest.raises(IntegrityError), transaction.atomic():
        Share.objects.create(
            organization=owner.organization, credential_id=cred.id, grantor=owner, grantee=bob, **{"can_view": True, **fields}
        )


def test_database_rejects_self_grants_and_burning_a_normal_grant(owner, bob, cred):
    from django.utils import timezone

    with pytest.raises(IntegrityError), transaction.atomic():
        Share.objects.create(organization=owner.organization, credential_id=cred.id, grantor=owner, grantee=owner)
    with pytest.raises(IntegrityError), transaction.atomic():
        Share.objects.create(organization=owner.organization, credential_id=cred.id, grantor=owner, grantee=bob, burned_at=timezone.now())


def test_access_resolution_refuses_other_organizations_even_if_a_grant_row_exists(owner, make_user, org_b, cred):
    """Defence in depth: views already scope by organization, but the resolver must not trust that.
    Simulates a corrupt/forged grant row pointing at a user in another tenant."""
    from apps.core.api_errors import NoAccess
    from apps.sharing.access import resolve_access
    from apps.vault.models import Credential

    outsider = make_user(org_b, "EMPLOYEE")
    Share.objects.create(organization=owner.organization, credential_id=cred.id, grantor=owner, grantee=outsider)
    with pytest.raises(NoAccess):
        resolve_access(outsider, Credential.objects.get(pk=cred.id))