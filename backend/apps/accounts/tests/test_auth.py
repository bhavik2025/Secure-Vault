import pytest
from django.contrib.auth.hashers import identify_hasher
from django.contrib.sessions.models import Session
from rest_framework.test import APIClient
from rest_framework.throttling import ScopedRateThrottle

from apps.accounts.models import AccountStatus, UserSession
from apps.audit.models import AuditEvent
from conftest import PASSWORD

LOGIN = "/api/auth/login/"
pytestmark = pytest.mark.django_db


def login(client, email, password=PASSWORD):
    return client.post(LOGIN, {"email": email, "password": password}, format="json")


def test_login_success_returns_identity_and_starts_session(api, make_user, org_a):
    user = make_user(org_a, "EMPLOYEE")
    resp = login(api, user.email)
    assert resp.status_code == 200
    assert resp.json()["email"] == user.email
    assert resp.json()["roles"] == ["EMPLOYEE"]
    assert "sessionid" in resp.cookies
    assert resp.cookies["sessionid"]["httponly"]  # JS can never read the session cookie
    assert api.get("/api/auth/me/").status_code == 200
    assert UserSession.objects.filter(user=user).count() == 1


def test_login_is_case_insensitive_on_email(api, make_user, org_a):
    user = make_user(org_a, "EMPLOYEE", email="mixed@org-a.example")
    assert login(api, "MiXeD@Org-A.example").status_code == 200
    assert user.email == "mixed@org-a.example"


def test_password_is_stored_hashed_not_plain(make_user, org_a):
    user = make_user(org_a)
    assert user.password != PASSWORD and PASSWORD not in user.password
    assert identify_hasher(user.password) is not None


def test_failures_are_indistinguishable_to_the_client(api, make_user, org_a):
    user = make_user(org_a)
    suspended = make_user(org_a, status=AccountStatus.SUSPENDED)
    responses = [
        login(api, user.email, "wrong-password"),
        login(api, "nobody@org-a.example"),
        login(api, suspended.email),
    ]
    assert {r.status_code for r in responses} == {401}
    assert len({r.content for r in responses}) == 1  # identical body: no account enumeration


@pytest.mark.parametrize("st", [AccountStatus.SUSPENDED, AccountStatus.DEACTIVATED, AccountStatus.INVITED])
def test_non_active_accounts_cannot_log_in_and_reason_is_audited(api, make_user, org_a, st):
    user = make_user(org_a, status=st)
    assert login(api, user.email).status_code == 401
    ev = AuditEvent.objects.get(action="LOGIN", outcome="DENIED")
    assert ev.reason_code == f"account_{st.lower()}"
    assert "sessionid" not in api.cookies or api.get("/api/auth/me/").status_code == 403


def test_login_audit_never_contains_the_password(api, make_user, org_a):
    user = make_user(org_a)
    login(api, user.email, "wrong-Secret-Pa55")
    login(api, user.email)
    blob = " ".join(
        f"{e.actor_email}{e.reason_code}{e.metadata}{e.target_id}" for e in AuditEvent.objects.all()
    )
    assert "wrong-Secret-Pa55" not in blob and PASSWORD not in blob


def test_password_typed_into_email_box_is_not_logged(api, org_a):
    api.post(LOGIN, {"email": "Hunter2-not-email", "password": "x"}, format="json")  # fails validation
    api.post(LOGIN, {"email": "a@b.co", "password": "x"}, format="json")
    assert not AuditEvent.objects.filter(actor_email__icontains="hunter2").exists()


def test_login_requires_csrf_token(make_user, org_a):
    user = make_user(org_a)
    strict = APIClient(enforce_csrf_checks=True)
    resp = strict.post(LOGIN, {"email": user.email, "password": PASSWORD}, format="json")
    assert resp.status_code == 403
    # With a valid token the same request succeeds.
    strict.get("/api/auth/csrf/")
    token = strict.cookies["csrftoken"].value
    ok = strict.post(
        LOGIN, {"email": user.email, "password": PASSWORD}, format="json", HTTP_X_CSRFTOKEN=token
    )
    assert ok.status_code == 200


def test_session_key_rotates_on_login(api, make_user, org_a):
    user = make_user(org_a)
    session = api.session
    session["anon"] = 1
    session.save()
    before = api.cookies["sessionid"].value
    login(api, user.email)
    assert api.cookies["sessionid"].value != before  # anti session-fixation


def test_logout_destroys_the_server_side_session(api, make_user, org_a):
    user = make_user(org_a)
    login(api, user.email)
    key = api.cookies["sessionid"].value
    assert api.post("/api/auth/logout/").status_code == 204
    assert not Session.objects.filter(session_key=key).exists()
    assert api.get("/api/auth/me/").status_code == 403
    assert AuditEvent.objects.filter(action="LOGOUT", actor=user).exists()
    assert not UserSession.objects.filter(user=user).exists()


def test_anonymous_cannot_reach_protected_endpoints(api):
    for path in ("/api/auth/me/", "/api/org/", "/api/org/departments/", "/api/org/employees/", "/api/audit/events/"):
        assert api.get(path).status_code == 403, path


def test_login_is_rate_limited(api, make_user, org_a, monkeypatch):
    from django.core.cache import cache

    cache.clear()
    monkeypatch.setattr(ScopedRateThrottle, "THROTTLE_RATES", {"login": "3/min"})
    user = make_user(org_a)
    codes = [login(api, user.email, "bad").status_code for _ in range(5)]
    assert codes[:3] == [401, 401, 401] and codes[3:] == [429, 429]
    cache.clear()


# --- Test #11: deactivation / suspension and session invalidation -----------------------

def test_suspending_a_user_kills_their_live_session_immediately(make_user, org_a):
    admin = make_user(org_a, "PLATFORM_ADMIN")
    victim = make_user(org_a, "EMPLOYEE")
    victim_client = APIClient()
    assert login(victim_client, victim.email).status_code == 200
    assert victim_client.get("/api/auth/me/").status_code == 200

    admin_client = APIClient()
    admin_client.force_login(admin)
    resp = admin_client.post(
        f"/api/org/employees/{victim.pk}/status/", {"status": "SUSPENDED", "reason": "investigation"}, format="json"
    )
    assert resp.status_code == 200
    assert victim_client.get("/api/auth/me/").status_code == 403
    assert not UserSession.objects.filter(user=victim).exists()


def test_session_of_a_status_flipped_directly_is_rejected_without_any_sweep(api, make_user, org_a):
    """Even if status changes outside our service (e.g. a shell), is_active is checked per request."""
    user = make_user(org_a)
    login(api, user.email)
    user.status = AccountStatus.DEACTIVATED
    user.save(update_fields=["status"])
    assert api.get("/api/auth/me/").status_code == 403
    assert login(api, user.email).status_code == 401
