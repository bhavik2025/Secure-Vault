import pytest
from rest_framework.throttling import ScopedRateThrottle

GEN, CHECK = "/api/vault/password/generate/", "/api/vault/password/check/"
pytestmark = pytest.mark.django_db


def test_generate_defaults_to_a_policy_compliant_password(emp_client):
    resp = emp_client.post(GEN, {}, format="json")
    body = resp.json()
    assert resp.status_code == 200 and len(body["password"]) == 20
    assert body["policy"] == {"min_length": 12, "require_symbols": True, "max_age_days": 90}
    assert body["strength"]["bits"] > 80 and body["strength"]["label"] in ("STRONG", "VERY_STRONG")
    assert resp["Cache-Control"] == "no-store"


def test_generated_password_is_accepted_by_the_credential_api(emp_client):
    pw = emp_client.post(GEN, {"length": 16}, format="json").json()["password"]
    assert emp_client.post("/api/vault/credentials/", {"title": "Gen", "password": pw}, format="json").status_code == 201


def test_default_length_follows_a_stricter_policy(emp_client, set_policy):
    set_policy(min_length=40)
    assert len(emp_client.post(GEN, {}, format="json").json()["password"]) == 40


def test_policy_limits_what_can_be_requested(emp_client, set_policy):
    resp = emp_client.post(GEN, {"length": 10}, format="json")
    assert resp.status_code == 403 and resp.json()["code"] == "below_min_length"
    resp = emp_client.post(GEN, {"symbols": False}, format="json")
    assert resp.status_code == 403 and resp.json()["code"] == "symbols_required"
    set_policy(require_symbols=False, min_length=8)
    ok = emp_client.post(GEN, {"length": 8, "symbols": False}, format="json").json()["password"]
    assert len(ok) == 8 and ok.isalnum()


@pytest.mark.parametrize("body", [{"length": 7}, {"length": 129}, {"length": "x"}, {"lowercase": "maybe"}])
def test_generate_validates_input(emp_client, body):
    assert emp_client.post(GEN, body, format="json").status_code == 400


def test_generate_requires_at_least_one_class(emp_client, set_policy):
    set_policy(require_symbols=False)
    resp = emp_client.post(GEN, {"lowercase": False, "uppercase": False, "digits": False, "symbols": False}, format="json")
    assert resp.status_code == 400


def test_check_reports_strength_and_policy_violations_without_echoing(emp_client):
    resp = emp_client.post(CHECK, {"password": "hunter2"}, format="json")
    body = resp.json()
    assert resp.status_code == 200 and body["compliant"] is False and len(body["policy_violations"]) == 2
    assert body["strength"]["label"] == "VERY_WEAK" and "hunter2" not in resp.content.decode()
    good = emp_client.post(CHECK, {"password": "Zx9#kLm2$Qw8!"}, format="json").json()
    assert good["compliant"] is True and good["policy_violations"] == []


def test_check_requires_a_password_field(emp_client):
    assert emp_client.post(CHECK, {}, format="json").status_code == 400


def test_password_utilities_are_rate_limited(emp_client, monkeypatch):
    from django.core.cache import cache

    cache.clear()
    monkeypatch.setattr(ScopedRateThrottle, "THROTTLE_RATES", {"vault_secret": "3/min"})
    codes = [emp_client.post(CHECK, {"password": "abc"}, format="json").status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    cache.clear()
