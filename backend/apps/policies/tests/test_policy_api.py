import threading

import pytest
from django.db import IntegrityError, connections, transaction

from apps.audit.models import AuditEvent
from apps.policies.models import SecurityPolicy

pytestmark = pytest.mark.django_db
URL = "/api/org/security-policies/"
NEW = {"name": "Strict", "min_length": 16, "require_symbols": True, "max_age_days": 60, "allow_view_once": False, "require_device_trust": True}


@pytest.fixture
def admin(make_user, org_a):
    return make_user(org_a, "PLATFORM_ADMIN")


def active(org):
    return SecurityPolicy.objects.get(organization=org, is_active=True)


def test_new_organizations_get_a_sensible_active_default_policy(org_a):
    p = active(org_a)
    assert (p.name, p.min_length, p.require_symbols, p.max_age_days, p.allow_view_once, p.require_device_trust) == (
        "Default Policy", 12, True, 90, True, False,
    )


def test_create_adds_an_inactive_policy_and_audits_it(api_as, admin, org_a):
    resp = api_as(admin).post(URL, NEW, format="json")
    assert resp.status_code == 201 and resp.json()["is_active"] is False
    assert active(org_a).name == "Default Policy"  # unchanged
    ev = AuditEvent.objects.get(action="POLICY_CHANGE", reason_code="created")
    assert ev.target_type == "security_policy" and ev.outcome == "SUCCESS"
    assert ev.metadata["changes"]["min_length"]["to"] == 16


def test_first_policy_of_an_organization_becomes_active(api_as, admin, org_a):
    SecurityPolicy.objects.filter(organization=org_a).delete()
    assert api_as(admin).post(URL, NEW, format="json").json()["is_active"] is True


def test_is_active_cannot_be_set_through_create_or_patch(api_as, admin, org_a):
    c = api_as(admin)
    new_id = c.post(URL, {**NEW, "is_active": True}, format="json").json()["id"]
    c.patch(f"{URL}{new_id}/", {"is_active": True}, format="json")
    assert SecurityPolicy.objects.filter(organization=org_a, is_active=True).count() == 1
    assert active(org_a).name == "Default Policy"


def test_update_active_policy_is_audited_with_readable_values_and_takes_effect(api_as, admin, org_a):
    c = api_as(admin)
    pid = active(org_a).pk
    resp = c.patch(f"{URL}{pid}/", {"min_length": 20, "allow_view_once": False}, format="json")
    assert resp.status_code == 200
    ev = AuditEvent.objects.get(action="POLICY_CHANGE", reason_code="updated")
    assert ev.metadata["changes"] == {
        "min_length": {"from": 12, "to": 20}, "allow_view_once": {"from": True, "to": False},
    }
    eff = c.get(URL + "active/").json()
    assert eff["min_length"] == 20 and eff["allow_view_once"] is False and eff["source"] == "organization"


def test_noop_update_is_not_audited(api_as, admin, org_a):
    api_as(admin).patch(f"{URL}{active(org_a).pk}/", {"min_length": 12}, format="json")
    assert not AuditEvent.objects.filter(action="POLICY_CHANGE").exists()


def test_activate_switches_the_single_active_policy_and_audits(api_as, admin, org_a):
    c = api_as(admin)
    new_id = c.post(URL, NEW, format="json").json()["id"]
    resp = c.post(f"{URL}{new_id}/activate/")
    assert resp.status_code == 200 and resp.json()["is_active"] is True
    assert SecurityPolicy.objects.filter(organization=org_a, is_active=True).count() == 1
    assert active(org_a).pk == new_id
    ev = AuditEvent.objects.get(reason_code="activated")
    assert ev.metadata["previous_active"] == "Default Policy"
    assert c.get(URL + "active/").json()["min_length"] == 16


def test_activating_the_already_active_policy_is_a_noop(api_as, admin, org_a):
    assert api_as(admin).post(f"{URL}{active(org_a).pk}/activate/").status_code == 200
    assert not AuditEvent.objects.filter(reason_code="activated").exists()


def test_policies_are_never_deleted(api_as, admin, org_a):
    assert api_as(admin).delete(f"{URL}{active(org_a).pk}/").status_code == 405


# --- validation ------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "patch",
    [
        {"min_length": 7}, {"min_length": 129}, {"min_length": "abc"}, {"min_length": None},
        {"max_age_days": 0}, {"max_age_days": 731}, {"max_age_days": -5}, {"max_age_days": "x"},
        {"require_symbols": "maybe"}, {"name": "<script>"}, {"name": "x"},
    ],
)
def test_invalid_policy_values_are_rejected(api_as, admin, org_a, patch):
    resp = api_as(admin).post(URL, {**NEW, **patch}, format="json")
    assert resp.status_code == 400, (patch, resp.json())
    assert SecurityPolicy.objects.filter(organization=org_a).count() == 1  # only the default


def test_boundary_values_and_no_expiry_are_valid(api_as, admin):
    c = api_as(admin)
    assert c.post(URL, {**NEW, "name": "Low", "min_length": 8, "max_age_days": 1}, format="json").status_code == 201
    assert c.post(URL, {**NEW, "name": "High", "min_length": 128, "max_age_days": 730}, format="json").status_code == 201
    assert c.post(URL, {**NEW, "name": "Never", "max_age_days": None}, format="json").status_code == 201


def test_duplicate_policy_name_rejected_case_insensitively(api_as, admin):
    assert api_as(admin).post(URL, {**NEW, "name": "default policy"}, format="json").status_code == 400


def test_database_enforces_ranges_and_single_active_even_if_api_is_bypassed(org_a):
    with pytest.raises(IntegrityError), transaction.atomic():
        SecurityPolicy.objects.create(organization=org_a, name="Weak", min_length=3)
    with pytest.raises(IntegrityError), transaction.atomic():
        SecurityPolicy.objects.create(organization=org_a, name="Second active", is_active=True)


# --- permissions & isolation -----------------------------------------------------------------

@pytest.mark.parametrize("role", ["EMPLOYEE", "DEPARTMENT_MANAGER"])
def test_roles_without_policies_view_cannot_even_list(api_as, make_user, org_a, role):
    assert api_as(make_user(org_a, role)).get(URL).status_code == 403


def test_security_admin_can_read_but_not_change_policies(api_as, make_user, org_a):
    c = api_as(make_user(org_a, "SECURITY_ADMIN"))
    pid = active(org_a).pk
    assert c.get(URL).status_code == 200 and c.get(f"{URL}{pid}/").status_code == 200
    assert c.post(URL, NEW, format="json").status_code == 403
    assert c.patch(f"{URL}{pid}/", {"min_length": 8}, format="json").status_code == 403
    assert c.post(f"{URL}{pid}/activate/").status_code == 403
    assert active(org_a).min_length == 12


def test_any_member_can_read_the_effective_policy_but_nothing_else(api_as, make_user, org_a):
    data = api_as(make_user(org_a, "EMPLOYEE")).get(URL + "active/").json()
    assert data["min_length"] == 12 and data["source"] == "organization"
    assert set(data) == {"name", "min_length", "require_symbols", "max_age_days", "allow_view_once", "require_device_trust", "source"}


def test_anonymous_is_rejected(api):
    assert api.get(URL).status_code == 403 and api.get(URL + "active/").status_code == 403


def test_cross_organization_isolation(api_as, admin, make_user, org_a, org_b):
    b_policy = active(org_b)
    c = api_as(admin)
    assert [r["id"] for r in c.get(URL).json()["results"]] == [active(org_a).pk]
    assert c.get(f"{URL}{b_policy.pk}/").status_code == 404
    assert c.patch(f"{URL}{b_policy.pk}/", {"min_length": 8}, format="json").status_code == 404
    assert c.post(f"{URL}{b_policy.pk}/activate/").status_code == 404
    c.patch(f"{URL}{active(org_a).pk}/", {"min_length": 30}, format="json")
    b_view = api_as(make_user(org_b, "EMPLOYEE")).get(URL + "active/").json()
    assert b_view["min_length"] == 12  # org A's change never leaks into org B


def test_organization_in_body_is_ignored(api_as, admin, org_a, org_b):
    pid = api_as(admin).post(URL, {**NEW, "organization": org_b.id}, format="json").json()["id"]
    assert SecurityPolicy.objects.get(pk=pid).organization_id == org_a.id


# --- concurrency -----------------------------------------------------------------------------

@pytest.mark.django_db(transaction=True)
def test_concurrent_activations_leave_exactly_one_active_policy(org_a, make_user):
    from apps.policies.services import activate_policy

    actor = make_user(org_a, "PLATFORM_ADMIN")
    policies = [SecurityPolicy.objects.create(organization=org_a, name=f"P{i}") for i in range(6)]
    errors = []

    def worker(p):
        try:
            activate_policy(policy=SecurityPolicy.objects.get(pk=p.pk), actor=actor)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=worker, args=(p,)) for p in policies]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors
    assert SecurityPolicy.objects.filter(organization=org_a, is_active=True).count() == 1
