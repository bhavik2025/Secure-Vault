import logging
import uuid

import pytest
from django.urls import get_resolver

from apps.audit.models import AuditEvent
from apps.vault.crypto import DecryptionError
from apps.vault.models import Credential, SecureNote
from apps.vault.services import unseal_for_reveal

from .conftest import plaintext_in

pytestmark = pytest.mark.django_db
CRED, NOTES = "/api/vault/credentials/", "/api/vault/notes/"


def _walk(patterns, prefix=""):
    for p in patterns:
        route = prefix + str(p.pattern)
        if hasattr(p, "url_patterns"):
            yield from _walk(p.url_patterns, route)
        else:
            yield route


# --- plaintext never persists or leaks ------------------------------------------------------------------

def test_secrets_appear_nowhere_in_the_database_logs_audit_or_responses(emp_client, caplog, db_dump):
    caplog.set_level(logging.DEBUG)
    pw1, pw2 = f"Zq!{uuid.uuid4().hex}", f"Wp#{uuid.uuid4().hex}"
    note_text, note_text2 = f"NOTE-{uuid.uuid4().hex}-body", f"NOTE2-{uuid.uuid4().hex}-body"
    probe = f"Pr!{uuid.uuid4().hex}"
    responses = []

    cid = emp_client.post(CRED, {"title": "Sec test", "username": "u1", "password": pw1}, format="json")
    responses.append(cid)
    cid = cid.json()["id"]
    responses.append(emp_client.patch(f"{CRED}{cid}/", {"password": pw2}, format="json"))
    nid = emp_client.post(NOTES, {"title": "Note", "content": note_text}, format="json")
    responses.append(nid)
    nid = nid.json()["id"]
    responses.append(emp_client.patch(f"{NOTES}{nid}/", {"content": note_text2}, format="json"))
    responses += [emp_client.get(CRED), emp_client.get(f"{CRED}{cid}/"), emp_client.get(NOTES), emp_client.get(f"{NOTES}{nid}/")]
    responses.append(emp_client.post("/api/vault/password/check/", {"password": probe}, format="json"))
    generated = emp_client.post("/api/vault/password/generate/", {}, format="json")
    responses.append(emp_client.post(CRED, {"title": "Bad", "password": "short"}, format="json"))  # validation error path

    dump, logs = db_dump(), caplog.text
    audit = " ".join(f"{e.metadata}{e.actor_email}{e.reason_code}{e.target_id}" for e in AuditEvent.objects.all())
    for secret in (pw1, pw2, note_text, note_text2, probe):
        assert not plaintext_in(secret, dump), "plaintext found in a database row"
        assert secret not in logs, "plaintext found in logs"
        assert secret not in audit, "plaintext found in audit data"
    generated_pw = generated.json()["password"]
    assert not plaintext_in(generated_pw, dump) and generated_pw not in logs and generated_pw not in audit
    for r in responses:  # no response (other than generate) ever carries a submitted secret
        for secret in (pw1, pw2, note_text, note_text2, probe):
            assert secret not in r.content.decode()


def test_stored_ciphertext_looks_random_not_structured(emp_client):
    bodies = [bytes(Credential.objects.get(pk=emp_client.post(CRED, {"title": f"c{i}", "password": "Aa1!" + "A" * 40}, format="json").json()["id"]).password_enc) for i in range(3)]
    # identical 44-char plaintexts -> ciphertext bytes differ everywhere that matters (nonce, tag, body)
    assert len({b[13:] for b in bodies}) == 3 and all(b"A" * 8 not in b for b in bodies)


# --- the database cannot be used to move secrets around -----------------------------------------------------

def _two_creds(client):
    a = Credential.objects.get(pk=client.post(CRED, {"title": "AA", "password": "Aa1!first-secret"}, format="json").json()["id"])
    b = Credential.objects.get(pk=client.post(CRED, {"title": "BB", "password": "Bb2@second-secret"}, format="json").json()["id"])
    return a, b


def test_ciphertext_copied_onto_another_record_does_not_decrypt(emp_client):
    a, b = _two_creds(emp_client)
    b.password_enc, b.wrapped_dek = a.password_enc, a.wrapped_dek  # a DB-level copy/paste attack
    with pytest.raises(DecryptionError):
        unseal_for_reveal(b)


def test_payload_copied_alone_or_wrapped_key_copied_alone_does_not_decrypt(emp_client):
    a, b = _two_creds(emp_client)
    keep = b.password_enc
    b.password_enc = a.password_enc
    with pytest.raises(DecryptionError):
        unseal_for_reveal(b)
    b.password_enc, b.wrapped_dek = keep, a.wrapped_dek
    with pytest.raises(DecryptionError):
        unseal_for_reveal(b)


def test_moving_a_record_to_another_organization_or_identity_breaks_decryption(emp_client, org_b):
    a, _ = _two_creds(emp_client)
    assert unseal_for_reveal(a) == "Aa1!first-secret"
    a.organization_id = org_b.id
    with pytest.raises(DecryptionError):
        unseal_for_reveal(a)
    a.organization_id = Credential.objects.get(pk=a.pk).organization_id
    a.uid = uuid.uuid4()
    with pytest.raises(DecryptionError):
        unseal_for_reveal(a)


def test_a_corrupted_stored_row_is_detected_not_silently_decrypted(emp_client):
    a, _ = _two_creds(emp_client)
    raw = bytearray(bytes(a.password_enc))
    raw[-1] ^= 0xFF
    Credential.objects.filter(pk=a.pk).update(password_enc=bytes(raw))
    with pytest.raises(DecryptionError):
        unseal_for_reveal(Credential.objects.get(pk=a.pk))


def test_note_ciphertext_cannot_be_used_as_a_credential_password(emp_client):
    nid = emp_client.post(NOTES, {"title": "NN", "content": "note body secret"}, format="json").json()["id"]
    note = SecureNote.objects.get(pk=nid)
    cred, _ = _two_creds(emp_client)
    cred.password_enc, cred.wrapped_dek, cred.uid = note.content_enc, note.wrapped_dek, note.uid
    with pytest.raises(DecryptionError):  # same org, same uid, but a different field/purpose
        unseal_for_reveal(cred)


# --- surface area ---------------------------------------------------------------------------------------------

def test_only_the_two_pipeline_gated_reveal_routes_exist():
    routes = list(_walk(get_resolver().url_patterns))
    for word in ("decrypt", "plaintext", "unseal"):
        assert not any(word in r.lower() for r in routes)
    # the DRF router also emits a ".<format>" suffix twin of every route; they are the same view
    reveal_routes = sorted(r for r in routes if "reveal" in r.lower() and "(?P<format>" not in r)
    assert len(reveal_routes) == 2 and all("(?P<pk>[^/.]+)/reveal" in r for r in reveal_routes), reveal_routes
    assert any("vault/credentials" in r for r in reveal_routes) and any("vault/notes" in r for r in reveal_routes)


def test_every_vault_endpoint_requires_authentication(api):
    for method, path in (
        ("get", CRED), ("post", CRED), ("get", NOTES), ("post", NOTES),
        ("post", "/api/vault/password/generate/"), ("post", "/api/vault/password/check/"),
    ):
        assert getattr(api, method)(path, {}, format="json").status_code == 403, (method, path)


def test_suspended_user_loses_vault_access_immediately(emp_client, emp):
    assert emp_client.get(CRED).status_code == 200
    emp.status = "SUSPENDED"
    emp.save(update_fields=["status"])
    assert emp_client.get(CRED).status_code == 403
    assert emp_client.post(CRED, {"title": "x1", "password": "Aa1!valid-secret"}, format="json").status_code == 403


def test_serializers_cannot_emit_encrypted_columns():
    from apps.vault.serializers import CredentialSerializer, SecureNoteSerializer

    forbidden = {"password_enc", "content_enc", "wrapped_dek", "kek_version", "enc_format", "blind_index", "uid"}
    for s in (CredentialSerializer, SecureNoteSerializer):
        assert not forbidden & set(s.Meta.fields)
