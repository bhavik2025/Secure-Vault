import pytest

from apps.audit.models import AuditEvent
from apps.organizations.models import Department

pytestmark = pytest.mark.django_db


@pytest.fixture
def world(make_user, org_a, org_b):
    """Two tenants, each with an admin, an employee and a department."""
    a_admin, b_admin = make_user(org_a, "PLATFORM_ADMIN"), make_user(org_b, "PLATFORM_ADMIN")
    a_emp, b_emp = make_user(org_a, "EMPLOYEE"), make_user(org_b, "EMPLOYEE")
    a_dep = Department.objects.create(organization=org_a, name="Engineering", code="ENG")
    b_dep = Department.objects.create(organization=org_b, name="Engineering", code="ENG")  # same code: allowed
    return dict(a_admin=a_admin, b_admin=b_admin, a_emp=a_emp, b_emp=b_emp, a_dep=a_dep, b_dep=b_dep)


def test_department_list_shows_only_own_organization(api_as, world):
    rows = api_as(world["a_admin"]).get("/api/org/departments/").json()["results"]
    assert [r["id"] for r in rows] == [world["a_dep"].id]


def test_other_tenants_department_is_404_not_403(api_as, world):
    c, foreign = api_as(world["a_admin"]), world["b_dep"]
    assert c.get(f"/api/org/departments/{foreign.id}/").status_code == 404
    assert c.patch(f"/api/org/departments/{foreign.id}/", {"name": "Hijack"}, format="json").status_code == 404
    foreign.refresh_from_db()
    assert foreign.name == "Engineering"


def test_organization_in_request_body_is_ignored(api_as, world, org_a, org_b):
    resp = api_as(world["a_admin"]).post(
        "/api/org/departments/", {"name": "Finance", "code": "FIN", "organization": org_b.id}, format="json"
    )
    assert resp.status_code == 201
    assert Department.objects.get(pk=resp.json()["id"]).organization_id == org_a.id


def test_department_head_must_belong_to_same_organization(api_as, world):
    resp = api_as(world["a_admin"]).post(
        "/api/org/departments/", {"name": "Legal", "code": "LEG", "head": world["b_emp"].id}, format="json"
    )
    assert resp.status_code == 400 and "head" in resp.json()
    ok = api_as(world["a_admin"]).post(
        "/api/org/departments/", {"name": "Legal", "code": "LEG", "head": world["a_emp"].id}, format="json"
    )
    assert ok.status_code == 201


def test_duplicate_code_rejected_inside_an_organization_only(api_as, world):
    resp = api_as(world["a_admin"]).post("/api/org/departments/", {"name": "Other", "code": "ENG"}, format="json")
    assert resp.status_code == 400 and "code" in resp.json()


def test_department_writes_are_audited(api_as, world):
    api_as(world["a_admin"]).post("/api/org/departments/", {"name": "Finance", "code": "FIN"}, format="json")
    ev = AuditEvent.objects.get(action="CREATE", target_type="department")
    assert ev.organization_id == world["a_admin"].organization_id and ev.outcome == "SUCCESS"


def test_employee_list_is_organization_scoped(api_as, world):
    emails = {r["email"] for r in api_as(world["a_admin"]).get("/api/org/employees/").json()["results"]}
    assert world["a_emp"].email in emails
    assert world["b_emp"].email not in emails and world["b_admin"].email not in emails


def test_cannot_change_status_of_another_tenants_user(api_as, world):
    resp = api_as(world["a_admin"]).post(
        f"/api/org/employees/{world['b_emp'].pk}/status/", {"status": "SUSPENDED", "reason": "attack"}, format="json"
    )
    assert resp.status_code == 404
    world["b_emp"].refresh_from_db()
    assert world["b_emp"].status == "ACTIVE"


def test_audit_trail_is_organization_scoped(api_as, world):
    api_as(world["b_emp"]).get("/api/audit/events/")  # org B denial event
    api_as(world["a_emp"]).get("/api/audit/events/")  # org A denial event
    rows = api_as(world["a_admin"]).get("/api/audit/events/").json()["results"]
    assert rows and all(r["actor_email"].endswith("@org-a.example") for r in rows)


def test_organization_endpoint_only_returns_own_org(api_as, world, org_a):
    assert api_as(world["a_admin"]).get("/api/org/").json()["id"] == org_a.id


def test_admin_has_no_route_to_foreign_or_secret_data(api_as, world):
    """Platform Admin is powerful over *administration*, but there is no endpoint (or
    permission) that exposes credential plaintext, and none that crosses tenants."""
    perms = world["a_admin"].app_permissions()
    assert not any("reveal" in p or "decrypt" in p for p in perms)
