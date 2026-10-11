import pytest

from apps.accounts.models import AccountStatus, Role
from apps.accounts.rbac import PERMISSIONS, ROLE_DEFINITIONS, assign_role
from apps.audit.models import AuditEvent

pytestmark = pytest.mark.django_db


# --- catalogue invariants (these protect the "no admin back door" rule) -------------------

def test_every_role_permission_exists_in_the_catalogue():
    for role, d in ROLE_DEFINITIONS.items():
        assert set(d["permissions"]) <= set(PERMISSIONS), role


def test_no_permission_grants_reading_other_peoples_secrets():
    banned = ("reveal", "decrypt", "any", "all", "*", "superuser")
    for codename in PERMISSIONS:
        assert not any(b in codename for b in banned), codename


def test_vault_use_is_the_only_vault_permission_and_every_role_has_it_equally():
    assert [c for c in PERMISSIONS if c.startswith("vault.")] == ["vault.use"]
    for role, d in ROLE_DEFINITIONS.items():
        assert [p for p in d["permissions"] if p.startswith("vault.")] == ["vault.use"], role


def test_security_admin_does_not_get_lockdown_by_default():
    assert "lockdown.trigger" not in ROLE_DEFINITIONS["SECURITY_ADMIN"]["permissions"]
    assert "lockdown.trigger" in ROLE_DEFINITIONS["PLATFORM_ADMIN"]["permissions"]


@pytest.mark.parametrize(
    "role,perm,expected",
    [
        ("PLATFORM_ADMIN", "users.manage", True),
        ("PLATFORM_ADMIN", "audit.view", True),
        ("SECURITY_ADMIN", "audit.view", True),
        ("SECURITY_ADMIN", "users.manage", False),
        ("SECURITY_ADMIN", "departments.manage", False),
        ("DEPARTMENT_MANAGER", "requests.approve", True),
        ("DEPARTMENT_MANAGER", "audit.view", False),
        ("EMPLOYEE", "audit.view", False),
        ("EMPLOYEE", "users.view", False),
        ("EMPLOYEE", "vault.use", True),
    ],
)
def test_role_permission_matrix(make_user, org_a, role, perm, expected):
    assert make_user(org_a, role).has_app_perm(perm) is expected


def test_seeding_is_idempotent(org_a):
    from apps.accounts.rbac import seed_roles

    seed_roles(org_a)
    seed_roles(org_a)
    assert Role.objects.filter(organization=org_a).count() == len(ROLE_DEFINITIONS)


# --- bypass attempts ---------------------------------------------------------------------

def test_django_superuser_flag_grants_no_application_permission(org_a):
    from apps.accounts.models import User

    root = User.objects.create_superuser("root@x.example", "Sup3r-Secret-Pass", organization=org_a)
    assert root.is_superuser and root.is_staff
    assert root.has_app_perm("audit.view") is False
    assert root.has_app_perm("users.manage") is False


def test_suspended_user_with_admin_role_has_no_permissions(make_user, org_a):
    admin = make_user(org_a, "PLATFORM_ADMIN", status=AccountStatus.SUSPENDED)
    assert admin.has_app_perm("audit.view") is False
    assert admin.app_permissions() == []


def test_role_from_another_organization_is_ignored(make_user, org_a, org_b):
    user = make_user(org_a, "EMPLOYEE")
    foreign_admin_role = Role.objects.get(organization=org_b, code="PLATFORM_ADMIN")
    user.roles.add(foreign_admin_role)  # simulate a bad data write / bug
    fresh = type(user).objects.get(pk=user.pk)
    assert fresh.has_app_perm("users.manage") is False
    assert fresh.app_permissions() == ["org.view", "vault.use"]


def test_assign_role_only_uses_the_users_own_organization(make_user, org_a, org_b):
    user = make_user(org_a)
    assign_role(user, "SECURITY_ADMIN")
    assert {r.organization_id for r in user.roles.all()} == {org_a.id}


# --- endpoint enforcement (server-side, regardless of what a UI shows) -------------------

def test_employee_cannot_read_audit_trail_and_denial_is_audited(make_user, api_as, org_a):
    emp = make_user(org_a, "EMPLOYEE")
    resp = api_as(emp).get("/api/audit/events/")
    assert resp.status_code == 403
    ev = AuditEvent.objects.get(action="AUTHZ_DENIED")
    assert ev.actor == emp and ev.outcome == "DENIED"
    assert ev.metadata["required"] == "audit.view" and ev.request_id


def test_read_only_role_cannot_write(make_user, api_as, org_a):
    mgr = make_user(org_a, "DEPARTMENT_MANAGER")
    c = api_as(mgr)
    assert c.get("/api/org/departments/").status_code == 200
    assert c.post("/api/org/departments/", {"name": "Ops", "code": "OPS"}, format="json").status_code == 403


def test_security_admin_cannot_change_account_status(make_user, api_as, org_a):
    sec, emp = make_user(org_a, "SECURITY_ADMIN"), make_user(org_a, "EMPLOYEE")
    resp = api_as(sec).post(
        f"/api/org/employees/{emp.pk}/status/", {"status": "SUSPENDED", "reason": "nope"}, format="json"
    )
    assert resp.status_code == 403
    emp.refresh_from_db()
    assert emp.status == AccountStatus.ACTIVE


def test_me_lists_permissions_for_ui_only(make_user, api_as, org_a):
    data = api_as(make_user(org_a, "EMPLOYEE")).get("/api/auth/me/").json()
    assert data["permissions"] == ["org.view", "vault.use"]
    assert data["organization"]["name"] == "Org A"


def test_status_change_rules(make_user, api_as, org_a):
    admin, emp = make_user(org_a, "PLATFORM_ADMIN"), make_user(org_a, "EMPLOYEE")
    c = api_as(admin)
    url = lambda u: f"/api/org/employees/{u.pk}/status/"  # noqa: E731
    assert c.post(url(admin), {"status": "SUSPENDED", "reason": "self"}, format="json").status_code == 400
    assert c.post(url(emp), {"status": "DEACTIVATED", "reason": "left company"}, format="json").status_code == 200
    # DEACTIVATED is terminal
    assert c.post(url(emp), {"status": "ACTIVE", "reason": "oops"}, format="json").status_code == 400
    assert c.post(url(emp), {"status": "BOGUS", "reason": "bad"}, format="json").status_code == 400
    ev = AuditEvent.objects.get(action="ACCOUNT_STATUS_CHANGE")
    assert ev.metadata["from"] == "ACTIVE" and ev.metadata["to"] == "DEACTIVATED"
