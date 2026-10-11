import logging
from datetime import timedelta

import pytest
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.vault.models import Credential, SecureNote

from .conftest import CRED_URL, GOOD, do_reveal, do_share, grant_row, lock, plaintext_in, unlock

pytestmark = pytest.mark.django_db


# --- who can reveal ---------------------------------------------------------------------------------------

def test_owner_reveal_returns_the_secret_with_no_store_and_is_audited(owner_client, owner, cred):
    resp = do_reveal(owner_client, cred.id)
    assert resp.status_code == 200
    assert resp.json() == {"password": GOOD, "via": "owner", "view_once": False, "grant_id": None}
    assert resp["Cache-Control"] == "no-store"
    ev = AuditEvent.objects.get(action="REVEAL")
    assert ev.outcome == "SUCCESS" and ev.actor_id == owner.pk and ev.target_id == str(cred.id) and ev.request_id
    assert GOOD not in str(ev.metadata) and ev.metadata["via"] == "owner"


def test_grantee_with_view_can_reveal(owner_client, api_as, bob, cred):
    do_share(owner_client, cred.id, bob)
    resp = do_reveal(api_as(bob), cred.id)
    assert resp.status_code == 200 and resp.json()["password"] == GOOD and resp.json()["via"] == "grant"
    assert AuditEvent.objects.get(action="REVEAL").metadata["grant_id"] == grant_row(cred.id, bob).pk


def test_strangers_get_404_and_it_is_audited(api_as, bob, cred):
    resp = do_reveal(api_as(bob), cred.id)
    assert resp.status_code == 404 and resp.json()["code"] == "no_access"
    ev = AuditEvent.objects.get(action="REVEAL")
    assert ev.outcome == "DENIED" and ev.reason_code == "no_access" and ev.actor_id == bob.pk
    assert GOOD not in resp.content.decode()


@pytest.mark.parametrize("role", ["PLATFORM_ADMIN", "SECURITY_ADMIN", "DEPARTMENT_MANAGER"])
def test_no_administrative_role_can_reveal_anothers_secret(api_as, make_user, org_a, cred, role):
    resp = do_reveal(api_as(make_user(org_a, role)), cred.id)
    assert resp.status_code == 404 and GOOD not in resp.content.decode()


def test_other_tenants_cannot_reveal(api_as, make_user, org_b, cred):
    assert do_reveal(api_as(make_user(org_b, "PLATFORM_ADMIN")), cred.id).status_code == 404


def test_anonymous_cannot_reveal(api, cred):
    assert do_reveal(api, cred.id).status_code == 403


def test_edit_or_share_grants_do_not_allow_reveal(owner_client, api_as, bob, carol, cred):
    do_share(owner_client, cred.id, bob, can_view=False, can_edit=True)
    do_share(owner_client, cred.id, carol, can_view=False, can_share=True)
    for who in (bob, carol):
        r = do_reveal(api_as(who), cred.id)
        assert r.status_code == 403 and r.json()["code"] == "view_not_granted"
    assert AuditEvent.objects.filter(action="REVEAL", outcome="DENIED", reason_code="view_not_granted").count() == 2


def test_suspended_user_cannot_reveal_even_with_a_grant(owner_client, api_as, bob, cred):
    do_share(owner_client, cred.id, bob)
    c = api_as(bob)
    bob.status = "SUSPENDED"
    bob.save(update_fields=["status"])
    assert do_reveal(c, cred.id).status_code == 403


def test_archived_credentials_cannot_be_revealed_by_anyone(owner_client, api_as, bob, cred):
    do_share(owner_client, cred.id, bob)
    owner_client.post(f"{CRED_URL}{cred.id}/archive/")
    assert do_reveal(owner_client, cred.id).json()["code"] == "record_archived"
    assert do_reveal(api_as(bob), cred.id).status_code == 404
    owner_client.post(f"{CRED_URL}{cred.id}/unarchive/")
    assert do_reveal(api_as(bob), cred.id).status_code == 200  # the grant itself was never touched


def test_reveal_only_works_with_post(owner_client, cred):
    assert owner_client.get(f"{CRED_URL}{cred.id}/reveal/").status_code == 405
    assert owner_client.put(f"{CRED_URL}{cred.id}/reveal/").status_code == 405


# --- expiry and revocation ---------------------------------------------------------------------------------

def test_expired_grants_fail(owner_client, api_as, bob, cred):
    do_share(owner_client, cred.id, bob, expires_in_hours=1)
    assert do_reveal(api_as(bob), cred.id).status_code == 200
    type(grant_row(cred.id, bob)).objects.filter(grantee=bob).update(expires_at=timezone.now() - timedelta(seconds=1))
    r = do_reveal(api_as(bob), cred.id)
    assert r.status_code == 403 and r.json()["code"] == "grant_expired"
    assert api_as(bob).get(f"{CRED_URL}{cred.id}/").json()["code"] == "grant_expired"
    assert AuditEvent.objects.filter(action="REVEAL", reason_code="grant_expired").exists()


def test_revoked_grants_fail(owner_client, api_as, bob, cred):
    sid = do_share(owner_client, cred.id, bob).json()["id"]
    owner_client.post(f"/api/vault/shares/{sid}/revoke/")
    r = do_reveal(api_as(bob), cred.id)
    assert r.status_code == 403 and r.json()["code"] == "grant_revoked"


def test_a_second_valid_grant_keeps_access_after_the_first_is_revoked(owner_client, api_as, bob, carol, cred):
    do_share(owner_client, cred.id, carol, can_share=True)
    first = do_share(owner_client, cred.id, bob).json()["id"]
    do_share(api_as(carol), cred.id, bob)
    owner_client.post(f"/api/vault/shares/{first}/revoke/")
    assert do_reveal(api_as(bob), cred.id).status_code == 200  # still has carol's grant


# --- lockdown, independent of any push notification ----------------------------------------------------------------

def test_global_lockdown_blocks_decryption_for_everyone_including_the_owner(owner_client, api_as, owner, bob, cred):
    do_share(owner_client, cred.id, bob)
    state = lock(owner.organization, owner)
    for client in (owner_client, api_as(bob)):
        r = do_reveal(client, cred.id)
        assert r.status_code == 423 and r.json()["code"] == "lockdown_active" and GOOD not in r.content.decode()
    assert AuditEvent.objects.filter(action="REVEAL", outcome="DENIED", reason_code="lockdown_active").count() == 2
    unlock(state)
    assert do_reveal(owner_client, cred.id).status_code == 200


def test_user_scoped_lockdown_blocks_only_that_user(owner_client, api_as, owner, bob, carol, cred):
    do_share(owner_client, cred.id, bob)
    do_share(owner_client, cred.id, carol)
    lock(owner.organization, owner, scope="USER", target=bob)
    assert do_reveal(api_as(bob), cred.id).status_code == 423
    assert do_reveal(api_as(carol), cred.id).status_code == 200
    assert do_reveal(owner_client, cred.id).status_code == 200


def test_lockdown_in_another_organization_has_no_effect(owner_client, owner, org_b, make_user, cred):
    lock(org_b, make_user(org_b, "PLATFORM_ADMIN"))
    assert do_reveal(owner_client, cred.id).status_code == 200


def test_lockdown_is_enforced_on_the_very_next_request_with_no_websocket_involved(owner_client, owner, cred):
    assert do_reveal(owner_client, cred.id).status_code == 200
    state = lock(owner.organization, owner)  # a database row is all the server needs
    assert do_reveal(owner_client, cred.id).status_code == 423
    unlock(state)
    assert do_reveal(owner_client, cred.id).status_code == 200


def test_lockdown_also_stops_notes_from_being_revealed(owner_client, owner):
    nid = owner_client.post("/api/vault/notes/", {"title": "Note", "content": "token-123"}, format="json").json()["id"]
    lock(owner.organization, owner)
    assert owner_client.post(f"/api/vault/notes/{nid}/reveal/").status_code == 423


# --- device-trust policy (fails closed until the device module exists) -------------------------------------------------

def test_required_device_trust_denies_reveal_until_it_can_be_verified(owner_client, set_policy, cred):
    set_policy(require_device_trust=True)
    r = do_reveal(owner_client, cred.id)
    assert r.status_code == 403 and r.json()["code"] == "device_trust_unavailable"
    assert AuditEvent.objects.filter(action="REVEAL", reason_code="device_trust_unavailable").exists()
    set_policy(require_device_trust=False)
    assert do_reveal(owner_client, cred.id).status_code == 200


# --- notes ------------------------------------------------------------------------------------------------------------

def test_secure_note_reveal_is_owner_only(owner_client, api_as, bob):
    nid = owner_client.post("/api/vault/notes/", {"title": "Note", "content": "API_KEY=abc123"}, format="json").json()["id"]
    r = owner_client.post(f"/api/vault/notes/{nid}/reveal/")
    assert r.status_code == 200 and r.json()["content"] == "API_KEY=abc123" and "password" not in r.json()
    assert api_as(bob).post(f"/api/vault/notes/{nid}/reveal/").status_code == 404
    assert AuditEvent.objects.filter(action="REVEAL", target_type="secure_note").count() == 1


# --- decryption failure ---------------------------------------------------------------------------------------------------

def test_corrupted_ciphertext_gives_a_generic_error_and_is_audited_as_failure(owner_client, cred):
    raw = bytearray(bytes(Credential.objects.get(pk=cred.id).password_enc))
    raw[-1] ^= 0xFF
    Credential.objects.filter(pk=cred.id).update(password_enc=bytes(raw))
    r = do_reveal(owner_client, cred.id)
    assert r.status_code == 500 and r.json()["code"] == "decryption_failed"
    assert AuditEvent.objects.get(action="REVEAL").outcome == "FAILURE"


# --- nothing leaks outside the reveal response --------------------------------------------------------------------------------

def test_secret_appears_only_in_reveal_responses_never_in_logs_audit_or_database(
    owner_client, api_as, bob, cred, caplog, db_dump
):
    caplog.set_level(logging.DEBUG)
    do_share(owner_client, cred.id, bob, can_view=True, can_share=True)
    others = [
        api_as(bob).get(f"{CRED_URL}{cred.id}/"),
        api_as(bob).get("/api/vault/shared-with-me/"),
        owner_client.get(f"{CRED_URL}{cred.id}/shares/"),
        owner_client.get(f"{CRED_URL}{cred.id}/shares/tree/"),
        owner_client.get(CRED_URL),
        owner_client.get("/api/audit/events/"),
        api_as(bob).get("/api/notifications/"),
        do_reveal(api_as(bob), 999999),
    ]
    assert do_reveal(api_as(bob), cred.id).json()["password"] == GOOD
    audit = " ".join(f"{e.metadata}{e.reason_code}{e.actor_email}" for e in AuditEvent.objects.all())
    assert not plaintext_in(GOOD, db_dump()) and GOOD not in caplog.text and GOOD not in audit
    assert all(GOOD not in r.content.decode() for r in others)
