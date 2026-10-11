import pytest
from django.db import IntegrityError, transaction

from apps.audit.models import AuditEvent
from apps.catalog.models import ServiceCatalogEntry

pytestmark = pytest.mark.django_db
URL = "/api/org/services/"
VALID = {"name": "Prod Postgres", "category": "DATABASE", "base_url": "postgresql://db.internal", "default_port": 5432}


@pytest.fixture
def admin(make_user, org_a):
    return make_user(org_a, "PLATFORM_ADMIN")


@pytest.fixture
def service(org_a):
    return ServiceCatalogEntry.objects.create(organization=org_a, name="GitHub", base_url="https://github.com")


# --- CRUD ---------------------------------------------------------------------------------

def test_create_normalizes_and_scopes_to_organization(api_as, admin, org_a):
    resp = api_as(admin).post(URL, {**VALID, "base_url": "PostgreSQL://DB.Internal:5432/ops"}, format="json")
    assert resp.status_code == 201
    body = resp.json()
    assert body["base_url"] == "postgresql://db.internal:5432/ops" and body["status"] == "ACTIVE"
    assert ServiceCatalogEntry.objects.get(pk=body["id"]).organization_id == org_a.id


def test_list_retrieve_and_filters(api_as, admin, org_a):
    ServiceCatalogEntry.objects.create(organization=org_a, name="AWS Console", category="CLOUD", base_url="https://aws.amazon.com")
    ServiceCatalogEntry.objects.create(organization=org_a, name="Grafana", category="MONITORING", base_url="https://g.example.com", status="INACTIVE")
    c = api_as(admin)
    assert {r["name"] for r in c.get(URL).json()["results"]} == {"AWS Console", "Grafana"}
    assert [r["name"] for r in c.get(URL + "?category=CLOUD").json()["results"]] == ["AWS Console"]
    assert [r["name"] for r in c.get(URL + "?status=INACTIVE").json()["results"]] == ["Grafana"]
    assert [r["name"] for r in c.get(URL + "?q=aws").json()["results"]] == ["AWS Console"]
    pk = ServiceCatalogEntry.objects.get(name="AWS Console").pk
    assert c.get(f"{URL}{pk}/").json()["name"] == "AWS Console"


def test_update_records_old_and_new_values_in_audit(api_as, admin, service):
    resp = api_as(admin).patch(f"{URL}{service.pk}/", {"base_url": "https://github.example.com", "default_port": 443}, format="json")
    assert resp.status_code == 200
    ev = AuditEvent.objects.get(action="EDIT", target_type="service")
    assert ev.metadata["changes"]["base_url"] == {"from": "https://github.com", "to": "https://github.example.com"}
    assert ev.metadata["changes"]["default_port"] == {"from": None, "to": 443}  # readable, not scrubbed


def test_noop_update_writes_no_audit_event(api_as, admin, service):
    api_as(admin).patch(f"{URL}{service.pk}/", {"name": "GitHub"}, format="json")
    assert not AuditEvent.objects.filter(action="EDIT").exists()


def test_create_is_audited(api_as, admin):
    api_as(admin).post(URL, VALID, format="json")
    ev = AuditEvent.objects.get(action="CREATE", target_type="service")
    assert ev.outcome == "SUCCESS" and ev.metadata["name"] == "Prod Postgres" and ev.request_id


def test_status_cannot_be_changed_through_patch(api_as, admin, service):
    api_as(admin).patch(f"{URL}{service.pk}/", {"status": "INACTIVE"}, format="json")
    service.refresh_from_db()
    assert service.status == "ACTIVE"


def test_deactivate_and_activate_are_soft_and_audited(api_as, admin, service):
    c = api_as(admin)
    assert c.post(f"{URL}{service.pk}/deactivate/").json()["status"] == "INACTIVE"
    assert ServiceCatalogEntry.objects.filter(pk=service.pk).exists()  # still there
    assert c.post(f"{URL}{service.pk}/deactivate/").status_code == 200  # idempotent
    assert AuditEvent.objects.filter(reason_code="deactivated").count() == 1
    assert c.post(f"{URL}{service.pk}/activate/").json()["status"] == "ACTIVE"
    assert AuditEvent.objects.filter(reason_code="activated").count() == 1


def test_hard_delete_is_not_offered(api_as, admin, service):
    assert api_as(admin).delete(f"{URL}{service.pk}/").status_code == 405
    assert ServiceCatalogEntry.objects.filter(pk=service.pk).exists()


# --- permissions ---------------------------------------------------------------------------

def test_employee_sees_only_active_services(api_as, make_user, org_a, service):
    hidden = ServiceCatalogEntry.objects.create(organization=org_a, name="Old Tool", base_url="https://old.example.com", status="INACTIVE")
    c = api_as(make_user(org_a, "EMPLOYEE"))
    assert [r["name"] for r in c.get(URL).json()["results"]] == ["GitHub"]
    assert c.get(f"{URL}{hidden.pk}/").status_code == 404
    assert c.get(URL + "?status=INACTIVE").json()["results"] == []


@pytest.mark.parametrize("role", ["EMPLOYEE", "DEPARTMENT_MANAGER", "SECURITY_ADMIN"])
def test_only_services_manage_can_write(api_as, make_user, org_a, service, role):
    c = api_as(make_user(org_a, role))
    assert c.post(URL, VALID, format="json").status_code == 403
    assert c.patch(f"{URL}{service.pk}/", {"name": "Hacked"}, format="json").status_code == 403
    assert c.post(f"{URL}{service.pk}/deactivate/").status_code == 403
    service.refresh_from_db()
    assert service.name == "GitHub" and service.status == "ACTIVE"
    assert AuditEvent.objects.filter(action="AUTHZ_DENIED").count() == 3


def test_anonymous_is_rejected(api, service):
    assert api.get(URL).status_code == 403
    assert api.post(URL, VALID, format="json").status_code == 403


# --- validation / unsafe input -------------------------------------------------------------

@pytest.mark.parametrize(
    "bad_url",
    [
        "javascript:alert(1)", "data:text/html,<script>alert(1)</script>", "file:///etc/passwd",
        "ftp://files.example.com", "https://user:hunter2@host.example.com", "https://", "not a url",
        "https://exa mple.com", "https://host.example.com:99999", "https://host.example.com:0",
        "https://" + "a" * 500 + ".com", "",
    ],
)
def test_unsafe_or_malformed_base_urls_are_rejected(api_as, admin, bad_url):
    resp = api_as(admin).post(URL, {**VALID, "base_url": bad_url}, format="json")
    assert resp.status_code == 400 and "base_url" in resp.json()
    assert not ServiceCatalogEntry.objects.exists()


@pytest.mark.parametrize("bad_icon", ["http://cdn.example.com/i.png", "javascript:alert(1)", "ssh://host/i.png", "https://u:p@cdn.example.com/i.png"])
def test_icon_url_must_be_plain_https(api_as, admin, bad_icon):
    assert api_as(admin).post(URL, {**VALID, "icon_url": bad_icon}, format="json").status_code == 400


def test_icon_url_is_optional_and_normalized(api_as, admin):
    assert api_as(admin).post(URL, {**VALID, "icon_url": ""}, format="json").status_code == 201
    ok = api_as(admin).post(URL, {**VALID, "name": "Other", "icon_url": "HTTPS://CDN.Example.com/i.png"}, format="json")
    assert ok.json()["icon_url"] == "https://cdn.example.com/i.png"


@pytest.mark.parametrize("port", [0, -1, 65536, "abc", 1.5])
def test_invalid_ports_are_rejected(api_as, admin, port):
    assert api_as(admin).post(URL, {**VALID, "default_port": port}, format="json").status_code == 400


def test_port_is_optional_and_boundaries_are_valid(api_as, admin):
    c = api_as(admin)
    assert c.post(URL, {**VALID, "name": "A1", "default_port": None}, format="json").status_code == 201
    assert c.post(URL, {**VALID, "name": "A2", "default_port": 1}, format="json").status_code == 201
    assert c.post(URL, {**VALID, "name": "A3", "default_port": 65535}, format="json").status_code == 201


@pytest.mark.parametrize("name", ["<script>alert(1)</script>", "a", "x\x00y", "<b>bold</b>"])
def test_unsafe_names_are_rejected(api_as, admin, name):
    resp = api_as(admin).post(URL, {**VALID, "name": name}, format="json")
    assert resp.status_code == 400 and "name" in resp.json()


def test_unknown_category_is_rejected(api_as, admin):
    assert api_as(admin).post(URL, {**VALID, "category": "NOPE"}, format="json").status_code == 400


def test_duplicate_name_is_rejected_case_insensitively_per_organization(api_as, admin, make_user, org_b):
    c = api_as(admin)
    assert c.post(URL, VALID, format="json").status_code == 201
    assert c.post(URL, {**VALID, "name": "prod postgres"}, format="json").status_code == 400
    other_admin = make_user(org_b, "PLATFORM_ADMIN")
    assert api_as(other_admin).post(URL, VALID, format="json").status_code == 201  # same name, other tenant


def test_database_enforces_port_range_even_if_the_api_is_bypassed(org_a):
    with pytest.raises(IntegrityError), transaction.atomic():
        ServiceCatalogEntry.objects.create(organization=org_a, name="X1", base_url="https://x.example.com", default_port=70000)


# --- isolation -----------------------------------------------------------------------------

def test_cross_organization_access_is_404(api_as, admin, make_user, org_b):
    foreign = ServiceCatalogEntry.objects.create(organization=org_b, name="Secret Tool", base_url="https://s.example.com")
    c = api_as(admin)
    assert c.get(URL).json()["results"] == []
    assert c.get(f"{URL}{foreign.pk}/").status_code == 404
    assert c.patch(f"{URL}{foreign.pk}/", {"name": "Hijacked"}, format="json").status_code == 404
    assert c.post(f"{URL}{foreign.pk}/deactivate/").status_code == 404
    foreign.refresh_from_db()
    assert foreign.name == "Secret Tool" and foreign.status == "ACTIVE"


def test_organization_field_in_body_is_ignored(api_as, admin, org_a, org_b):
    resp = api_as(admin).post(URL, {**VALID, "organization": org_b.id}, format="json")
    assert ServiceCatalogEntry.objects.get(pk=resp.json()["id"]).organization_id == org_a.id
