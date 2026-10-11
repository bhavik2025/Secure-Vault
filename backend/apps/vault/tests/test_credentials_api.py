from datetime import timedelta

import pytest
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.catalog.models import ServiceCatalogEntry
from apps.vault.models import Credential
from apps.vault.services import unseal_for_reveal

from .conftest import GOOD, GOOD2

pytestmark = pytest.mark.django_db
URL = "/api/vault/credentials/"
MASK = "•" * 12


def create(client, **over):
    body = {"title": "Prod DB", "username": "svc_app", "password": GOOD, **over}
    return client.post(URL, body, format="json")


# --- create / representation ---------------------------------------------------------------------

def test_create_returns_masked_metadata_and_never_the_secret(emp_client):
    resp = create(emp_client)
    assert resp.status_code == 201
    body = resp.json()
    assert "password" not in body and body["password_masked"] == MASK and body["has_password"] is True
    assert GOOD not in resp.content.decode()
    assert resp["Cache-Control"] == "no-store"
    assert body["status"] == "ACTIVE" and body["owner"]["email"] and body["strength"]["bits"] > 0


def test_owner_sees_the_unguessable_request_code_used_for_access_requests(emp_client):
    body = create(emp_client).json()
    cred = Credential.objects.get(pk=body["id"])
    assert body["request_code"] == str(cred.uid)
    assert emp_client.get(f"{URL}{cred.pk}/").json()["request_code"] == str(cred.uid)


def test_stored_record_is_an_encrypted_envelope_not_plaintext(emp_client, emp, org_a):
    cred = Credential.objects.get(pk=create(emp_client).json()["id"])
    assert cred.organization_id == org_a.id and cred.owner_id == emp.id
    blob, wrapped = bytes(cred.password_enc), bytes(cred.wrapped_dek)
    assert blob[0] == 1 and len(blob) == 29 + len(GOOD) and len(wrapped) == 61
    assert GOOD.encode() not in blob + wrapped
    assert cred.kek_version == 1 and cred.enc_format == 1 and len(cred.blind_index) == 64
    assert unseal_for_reveal(cred) == GOOD  # internal path only; no HTTP route reaches it


def test_two_credentials_with_the_same_password_have_different_ciphertext(emp_client):
    a = Credential.objects.get(pk=create(emp_client, title="One").json()["id"])
    b = Credential.objects.get(pk=create(emp_client, title="Two").json()["id"])
    assert bytes(a.password_enc) != bytes(b.password_enc) and bytes(a.wrapped_dek) != bytes(b.wrapped_dek)
    assert a.blind_index == b.blind_index  # deterministic by design (reuse detection)


# --- expiry and policy enforcement -----------------------------------------------------------------

def test_default_expiry_comes_from_the_policy(emp_client):
    body = create(emp_client).json()
    assert body["expiry_date"] == str(timezone.now().date() + timedelta(days=90)) and body["expiry_state"] == "ok"


def test_explicit_expiry_within_policy_is_accepted(emp_client):
    day = str(timezone.now().date() + timedelta(days=30))
    assert create(emp_client, expiry_date=day).json()["expiry_date"] == day


@pytest.mark.parametrize("offset", [-1, 0, 91, 500])
def test_expiry_in_the_past_today_or_beyond_policy_max_is_rejected(emp_client, offset):
    day = str(timezone.now().date() + timedelta(days=offset))
    resp = create(emp_client, expiry_date=day)
    assert resp.status_code == 400 and "expiry_date" in resp.json()


def test_policy_that_requires_an_expiry_rejects_null(emp_client):
    assert create(emp_client, expiry_date=None).status_code == 400


def test_policy_without_max_age_allows_no_expiry(emp_client, set_policy):
    set_policy(max_age_days=None)
    body = create(emp_client).json()
    assert body["expiry_date"] is None and body["expiry_state"] == "none"
    assert create(emp_client, title="Far", expiry_date=str(timezone.now().date() + timedelta(days=2000))).status_code == 201


@pytest.mark.parametrize("pw", ["Short1!", "NoSymbolButLongEnough1", "short"])
def test_password_must_satisfy_the_security_policy(emp_client, pw):
    resp = create(emp_client, password=pw)
    assert resp.status_code == 400 and "password" in resp.json()
    assert pw not in resp.content.decode()  # the password is never echoed back
    assert not Credential.objects.exists()


def test_policy_changes_apply_to_the_next_request(emp_client, set_policy):
    set_policy(min_length=20)
    assert create(emp_client).status_code == 400
    set_policy(min_length=8, require_symbols=False)
    assert create(emp_client, password="plainpass1").status_code == 201


# --- field validation ---------------------------------------------------------------------------------

def test_password_is_required_on_create(emp_client):
    resp = emp_client.post(URL, {"title": "No pw"}, format="json")
    assert resp.status_code == 400 and "password" in resp.json()


@pytest.mark.parametrize(
    "over", [{"title": ""}, {"title": "<script>x</script>"}, {"username": "u" * 255}, {"category": "NOPE"}, {"password": "x" * 257}]
)
def test_invalid_fields_are_rejected(emp_client, over):
    assert create(emp_client, **over).status_code == 400


def test_tags_are_normalized_deduplicated_and_validated(emp_client):
    assert create(emp_client, tags=[" Prod ", "PROD", "db:primary"]).json()["tags"] == ["prod", "db:primary"]
    assert create(emp_client, tags=["<b>"]).status_code == 400
    assert create(emp_client, tags=[f"t{i}" for i in range(11)]).status_code == 400
    assert create(emp_client, tags=["x" * 40]).status_code == 400


def test_service_association_and_category_inheritance(emp_client, org_a):
    svc = ServiceCatalogEntry.objects.create(organization=org_a, name="AWS", category="CLOUD", base_url="https://aws.amazon.com")
    body = create(emp_client, service=svc.id).json()
    assert body["service"] == svc.id and body["service_name"] == "AWS" and body["category"] == "CLOUD"
    assert create(emp_client, service=svc.id, category="OTHER").json()["category"] == "OTHER"  # explicit wins


def test_service_must_exist_be_active_and_belong_to_the_organization(emp_client, org_a, org_b):
    foreign = ServiceCatalogEntry.objects.create(organization=org_b, name="Foreign", base_url="https://f.example.com")
    off = ServiceCatalogEntry.objects.create(organization=org_a, name="Off", base_url="https://o.example.com", status="INACTIVE")
    foreign_msg = create(emp_client, service=foreign.id).json()["service"]
    missing_msg = create(emp_client, service=999999).json()["service"]
    assert [m.split('"')[0] for m in foreign_msg] == [m.split('"')[0] for m in missing_msg]  # no existence oracle
    assert create(emp_client, service=off.id).status_code == 400


def test_existing_credential_keeps_a_service_that_was_later_deactivated(emp_client, org_a):
    svc = ServiceCatalogEntry.objects.create(organization=org_a, name="Later", base_url="https://l.example.com")
    cid = create(emp_client, service=svc.id).json()["id"]
    svc.status = "INACTIVE"
    svc.save()
    assert emp_client.patch(f"{URL}{cid}/", {"title": "Renamed", "service": svc.id}, format="json").status_code == 200


# --- ownership / isolation (least privilege) --------------------------------------------------------------

def test_other_users_in_the_same_organization_cannot_see_or_touch_it(emp_client, api_as, make_user, org_a):
    cid = create(emp_client).json()["id"]
    stranger = api_as(make_user(org_a, "EMPLOYEE"))
    assert stranger.get(URL).json()["results"] == []
    for call in (
        lambda: stranger.get(f"{URL}{cid}/"),
        lambda: stranger.patch(f"{URL}{cid}/", {"title": "Hijack"}, format="json"),
        lambda: stranger.post(f"{URL}{cid}/archive/"),
    ):
        assert call().status_code == 404
    assert Credential.objects.get(pk=cid).title == "Prod DB"


@pytest.mark.parametrize("role", ["PLATFORM_ADMIN", "SECURITY_ADMIN", "DEPARTMENT_MANAGER"])
def test_administrative_roles_get_no_access_to_other_peoples_credentials(emp_client, api_as, make_user, org_a, role):
    cid = create(emp_client).json()["id"]
    boss = api_as(make_user(org_a, role))
    assert boss.get(URL).json()["results"] == []
    assert boss.get(f"{URL}{cid}/").status_code == 404
    assert boss.patch(f"{URL}{cid}/", {"title": "x"}, format="json").status_code == 404


def test_other_organizations_cannot_see_it(emp_client, api_as, make_user, org_b):
    cid = create(emp_client).json()["id"]
    outsider = api_as(make_user(org_b, "PLATFORM_ADMIN"))
    assert outsider.get(URL).json()["results"] == [] and outsider.get(f"{URL}{cid}/").status_code == 404


def test_organization_and_owner_in_the_body_are_ignored(emp_client, emp, org_a, org_b, make_user):
    other = make_user(org_b, "EMPLOYEE")
    cred = Credential.objects.get(pk=create(emp_client, organization=org_b.id, owner=other.id).json()["id"])
    assert cred.organization_id == org_a.id and cred.owner_id == emp.id


def test_anonymous_requests_are_rejected(api):
    assert api.get(URL).status_code == 403 and api.post(URL, {}, format="json").status_code == 403


# --- update, rotation, archive -------------------------------------------------------------------------------

def test_metadata_update_leaves_the_encrypted_secret_untouched(emp_client):
    cid = create(emp_client).json()["id"]
    before = Credential.objects.get(pk=cid)
    assert emp_client.patch(f"{URL}{cid}/", {"title": "Renamed", "tags": ["x1"]}, format="json").status_code == 200
    after = Credential.objects.get(pk=cid)
    assert bytes(after.password_enc) == bytes(before.password_enc) and bytes(after.wrapped_dek) == bytes(before.wrapped_dek)
    assert after.title == "Renamed" and after.password_changed_at == before.password_changed_at
    ev = AuditEvent.objects.get(action="EDIT", reason_code="updated")
    assert "rotated" not in ev.metadata and ev.metadata["changes"]["title"] == {"from": "Prod DB", "to": "Renamed"}


def test_password_rotation_re_encrypts_with_new_dek_nonce_and_blind_index(emp_client):
    cid = create(emp_client).json()["id"]
    before = Credential.objects.get(pk=cid)
    resp = emp_client.patch(f"{URL}{cid}/", {"password": GOOD2}, format="json")
    assert resp.status_code == 200 and GOOD2 not in resp.content.decode()
    after = Credential.objects.get(pk=cid)
    assert bytes(after.password_enc) != bytes(before.password_enc) and bytes(after.wrapped_dek) != bytes(before.wrapped_dek)
    assert bytes(after.password_enc)[1:13] != bytes(before.password_enc)[1:13]
    assert after.blind_index != before.blind_index and after.password_changed_at > before.password_changed_at
    assert unseal_for_reveal(after) == GOOD2
    assert AuditEvent.objects.get(action="EDIT", reason_code="updated").metadata["rotated"] is True


def test_rotated_password_must_also_meet_policy(emp_client):
    cid = create(emp_client).json()["id"]
    assert emp_client.patch(f"{URL}{cid}/", {"password": "weak"}, format="json").status_code == 400
    assert unseal_for_reveal(Credential.objects.get(pk=cid)) == GOOD


def test_rotation_resets_expiry_to_policy_default_unless_given(emp_client):
    cid = create(emp_client, expiry_date=str(timezone.now().date() + timedelta(days=10))).json()["id"]
    body = emp_client.patch(f"{URL}{cid}/", {"password": GOOD2}, format="json").json()
    assert body["expiry_date"] == str(timezone.now().date() + timedelta(days=90))


def test_archive_unarchive_flow(emp_client):
    cid = create(emp_client).json()["id"]
    assert emp_client.post(f"{URL}{cid}/archive/").json()["status"] == "ARCHIVED"
    assert emp_client.post(f"{URL}{cid}/archive/").status_code == 200  # idempotent
    assert emp_client.get(URL).json()["results"] == []
    assert [r["id"] for r in emp_client.get(URL + "?status=ARCHIVED").json()["results"]] == [cid]
    assert emp_client.get(f"{URL}{cid}/").status_code == 200
    assert emp_client.patch(f"{URL}{cid}/", {"title": "Nope"}, format="json").status_code == 400  # must unarchive first
    assert emp_client.post(f"{URL}{cid}/unarchive/").json()["status"] == "ACTIVE"
    assert emp_client.patch(f"{URL}{cid}/", {"title": "Fine"}, format="json").status_code == 200
    assert sorted(AuditEvent.objects.filter(reason_code__in=["archived", "unarchived"]).values_list("reason_code", flat=True)) == [
        "archived", "unarchived",
    ]


def test_status_cannot_be_set_through_patch_and_hard_delete_is_not_offered(emp_client):
    cid = create(emp_client).json()["id"]
    emp_client.patch(f"{URL}{cid}/", {"status": "ARCHIVED"}, format="json")
    assert Credential.objects.get(pk=cid).status == "ACTIVE"
    assert emp_client.delete(f"{URL}{cid}/").status_code == 405 and Credential.objects.filter(pk=cid).exists()


def test_the_only_way_to_read_a_secret_is_the_post_reveal_action(emp_client):
    cid = create(emp_client).json()["id"]
    for suffix in ("decrypt/", "password/", "secret/", "copy/", "plaintext/"):
        assert emp_client.get(f"{URL}{cid}/{suffix}").status_code == 404
        assert emp_client.post(f"{URL}{cid}/{suffix}").status_code == 404
    assert emp_client.get(f"{URL}{cid}/reveal/").status_code == 405  # never GET: side effects, and cacheable
    assert emp_client.post(f"{URL}{cid}/reveal/").status_code == 200  # owner, full pipeline


# --- list: search, filters, ordering ------------------------------------------------------------------------------

def test_search_filters_and_ordering(emp_client, org_a):
    svc = ServiceCatalogEntry.objects.create(organization=org_a, name="GitHub", category="SOURCE_CONTROL", base_url="https://github.com")
    create(emp_client, title="Alpha", username="deploy_bot", tags=["ci"], service=svc.id)
    create(emp_client, title="Beta", username="root", category="DATABASE", tags=["prod", "db"])
    create(emp_client, title="Gamma", username="admin", category="DATABASE", tags=["prod"])

    def titles(qs):
        return [r["title"] for r in emp_client.get(URL + qs).json()["results"]]

    assert titles("") == ["Alpha", "Beta", "Gamma"]
    assert titles("?ordering=-title") == ["Gamma", "Beta", "Alpha"]
    assert titles("?q=deploy") == ["Alpha"] and titles("?q=github") == ["Alpha"] and titles("?q=BETA") == ["Beta"]
    assert titles("?category=DATABASE") == ["Beta", "Gamma"]
    assert titles("?tag=prod") == ["Beta", "Gamma"] and titles("?tag=db") == ["Beta"]
    assert titles(f"?service={svc.id}") == ["Alpha"] and titles("?service=abc") == []
    assert titles("?ordering=password_enc") == ["Alpha", "Beta", "Gamma"]  # unknown ordering ignored, no error
    data = emp_client.get(URL).json()
    assert data["count"] == 3 and {"next", "previous", "results"} <= set(data)


# --- hygiene signals (metadata only) ---------------------------------------------------------------------------------

def test_expiry_warnings(emp_client):
    passwords = {"exp": GOOD, "soon": GOOD2, "fine": "Lp5@wQe8#Zx1"}  # distinct, so no reuse warning interferes
    ids = {n: create(emp_client, title=n, password=pw).json()["id"] for n, pw in passwords.items()}
    today = timezone.now().date()
    Credential.objects.filter(pk=ids["exp"]).update(expiry_date=today - timedelta(days=1))
    Credential.objects.filter(pk=ids["soon"]).update(expiry_date=today + timedelta(days=5))
    rows = {r["title"]: r for r in emp_client.get(URL).json()["results"]}
    assert rows["exp"]["expiry_state"] == "expired" and "expired" in rows["exp"]["warnings"]
    assert rows["soon"]["expiry_state"] == "expiring_soon" and "expiring_soon" in rows["soon"]["warnings"]
    assert rows["fine"]["warnings"] == []
    assert [r["title"] for r in emp_client.get(URL + "?expiry=expired").json()["results"]] == ["exp"]
    assert [r["title"] for r in emp_client.get(URL + "?expiry=soon").json()["results"]] == ["soon"]


def test_weak_and_old_password_warnings(emp_client, set_policy):
    set_policy(min_length=8, require_symbols=False)
    weak_id = create(emp_client, title="weak", password="Abcd1234").json()["id"]
    old_id = create(emp_client, title="old").json()["id"]
    Credential.objects.filter(pk=old_id).update(password_changed_at=timezone.now() - timedelta(days=120))
    rows = {r["title"]: r for r in emp_client.get(URL).json()["results"]}
    assert "weak_password" in rows["weak"]["warnings"] and rows["weak"]["strength"]["label"] in ("VERY_WEAK", "WEAK")
    assert "older_than_policy_max_age" in rows["old"]["warnings"] and weak_id != old_id


def test_reuse_is_detected_within_the_owners_own_vault(emp_client):
    first = create(emp_client, title="one").json()
    assert first["reused_in_my_vault"] is False
    create(emp_client, title="two")
    rows = {r["title"]: r for r in emp_client.get(URL).json()["results"]}
    assert rows["one"]["reused_in_my_vault"] and rows["two"]["reused_in_my_vault"]
    assert "reused_in_my_vault" in rows["one"]["warnings"]
    emp_client.post(f"{URL}{rows['two']['id']}/archive/")  # archived copies no longer count
    assert emp_client.get(URL).json()["results"][0]["reused_in_my_vault"] is False


def test_reuse_is_never_revealed_across_users_so_it_cannot_be_used_as_a_guessing_oracle(emp_client, api_as, make_user, org_a):
    create(emp_client, title="mine")
    other = api_as(make_user(org_a, "EMPLOYEE"))
    probe = create(other, title="probe").json()  # same password as a colleague's credential
    assert probe["reused_in_my_vault"] is False and probe["warnings"] == []
    assert emp_client.get(URL).json()["results"][0]["reused_in_my_vault"] is False
    assert Credential.objects.values("blind_index").distinct().count() == 1  # equal in the DB, invisible via the API


def test_blind_index_is_never_returned(emp_client):
    cid = create(emp_client).json()["id"]
    text = emp_client.get(f"{URL}{cid}/").content.decode() + emp_client.get(URL).content.decode()
    assert Credential.objects.get(pk=cid).blind_index not in text
    assert not any(k in text for k in ("blind", "wrapped", "kek", "nonce", "ciphertext", "password_enc"))


# --- audit -------------------------------------------------------------------------------------------------------------------

def test_create_and_edit_are_audited_without_secrets_or_usernames(emp_client, emp):
    cid = create(emp_client, username="very_specific_username").json()["id"]
    emp_client.patch(f"{URL}{cid}/", {"username": "another_specific_username", "password": GOOD2}, format="json")
    events = list(AuditEvent.objects.filter(target_type="credential").order_by("id"))
    assert [(e.action, e.reason_code) for e in events] == [("CREATE", "created"), ("EDIT", "updated")]
    assert all(e.actor_id == emp.id and e.target_id == str(cid) and e.request_id for e in events)
    dump = " ".join(str(e.metadata) for e in events)
    for secret in (GOOD, GOOD2, "very_specific_username", "another_specific_username"):
        assert secret not in dump
    assert events[1].metadata["changes"]["username"] == {"changed": True} and events[1].metadata["rotated"] is True
