import pytest

from apps.audit.models import AuditEvent
from apps.vault.models import SecureNote
from apps.vault.services import unseal_for_reveal

pytestmark = pytest.mark.django_db
URL = "/api/vault/notes/"
MASK = "•" * 12
CONTENT = "API_KEY=sk_live_51Hx\nDB_URL=postgres://u:p@host/db\néè unicode \U0001f510"


def create(client, **over):
    return client.post(URL, {"title": "Prod API keys", "content": CONTENT, **over}, format="json")


def test_create_stores_only_an_encrypted_envelope_and_returns_a_mask(emp_client):
    resp = create(emp_client, tags=["API", "prod"])
    assert resp.status_code == 201
    body = resp.json()
    assert "content" not in body and body["content_masked"] == MASK and body["tags"] == ["api", "prod"]
    assert CONTENT not in resp.content.decode() and "sk_live" not in resp.content.decode()
    assert resp["Cache-Control"] == "no-store"
    note = SecureNote.objects.get(pk=body["id"])
    blob = bytes(note.content_enc)
    assert blob[0] == 1 and len(blob) == 29 + len(CONTENT.encode()) and len(bytes(note.wrapped_dek)) == 61
    assert b"sk_live" not in blob and unseal_for_reveal(note) == CONTENT  # multi-line + unicode preserved


def test_content_is_required_non_blank_and_size_limited(emp_client):
    assert emp_client.post(URL, {"title": "Empty"}, format="json").status_code == 400
    assert create(emp_client, content="").status_code == 400
    assert create(emp_client, content="x" * 20_000).status_code == 201
    assert create(emp_client, content="x" * 20_001).status_code == 400


def test_notes_are_not_subject_to_password_rules(emp_client):
    assert create(emp_client, content="short").status_code == 201  # API keys/tokens are free-form


def test_title_is_validated(emp_client):
    assert create(emp_client, title="<img src=x>").status_code == 400
    assert create(emp_client, title="a").status_code == 400


def test_update_title_keeps_ciphertext_and_content_change_re_encrypts(emp_client):
    nid = create(emp_client).json()["id"]
    before = SecureNote.objects.get(pk=nid)
    emp_client.patch(f"{URL}{nid}/", {"title": "Renamed"}, format="json")
    same = SecureNote.objects.get(pk=nid)
    assert bytes(same.content_enc) == bytes(before.content_enc) and same.title == "Renamed"
    resp = emp_client.patch(f"{URL}{nid}/", {"content": "new secret token 12345"}, format="json")
    assert "new secret token" not in resp.content.decode()
    after = SecureNote.objects.get(pk=nid)
    assert bytes(after.content_enc) != bytes(before.content_enc) and bytes(after.wrapped_dek) != bytes(before.wrapped_dek)
    assert unseal_for_reveal(after) == "new secret token 12345"
    assert AuditEvent.objects.filter(target_type="secure_note", metadata__rotated=True).count() == 1


def test_isolation_between_users_roles_and_organizations(emp_client, api_as, make_user, org_a, org_b):
    nid = create(emp_client).json()["id"]
    for who in (make_user(org_a, "EMPLOYEE"), make_user(org_a, "PLATFORM_ADMIN"), make_user(org_b, "PLATFORM_ADMIN")):
        c = api_as(who)
        assert c.get(URL).json()["results"] == []
        assert c.get(f"{URL}{nid}/").status_code == 404
        assert c.patch(f"{URL}{nid}/", {"title": "x1"}, format="json").status_code == 404
        assert c.post(f"{URL}{nid}/archive/").status_code == 404


def test_archive_flow_search_and_no_delete_or_reveal(emp_client):
    nid = create(emp_client).json()["id"]
    create(emp_client, title="Other note")
    assert [r["title"] for r in emp_client.get(URL + "?q=other").json()["results"]] == ["Other note"]
    assert emp_client.post(f"{URL}{nid}/archive/").json()["status"] == "ARCHIVED"
    assert [r["title"] for r in emp_client.get(URL).json()["results"]] == ["Other note"]
    assert emp_client.patch(f"{URL}{nid}/", {"title": "nope"}, format="json").status_code == 400
    assert emp_client.post(f"{URL}{nid}/unarchive/").json()["status"] == "ACTIVE"
    assert emp_client.delete(f"{URL}{nid}/").status_code == 405
    assert emp_client.get(f"{URL}{nid}/reveal/").status_code == 405  # reveal is POST-only
    assert emp_client.get(f"{URL}{nid}/decrypt/").status_code == 404


def test_anonymous_is_rejected(api):
    assert api.get(URL).status_code == 403


def test_audit_records_the_event_but_never_the_content(emp_client):
    nid = create(emp_client).json()["id"]
    emp_client.patch(f"{URL}{nid}/", {"content": "another secret"}, format="json")
    events = AuditEvent.objects.filter(target_type="secure_note").order_by("id")
    assert [e.action for e in events] == ["CREATE", "EDIT"]
    blob = " ".join(str(e.metadata) for e in events)
    assert "sk_live" not in blob and "another secret" not in blob and "postgres://" not in blob
