import threading

import pytest
from django.db import DatabaseError, connection, connections, transaction
from django.test import override_settings

from apps.audit.models import AuditEvent, AuditImmutableError
from apps.audit.scrub import REDACTED, scrub
from apps.audit.services import GENESIS_HASH, record, verify_chain


def make_event(org=None, **kw):
    return record(action="LOGIN", outcome="SUCCESS", organization=org, actor_email="a@b.co", **kw)


def as_table_owner(sql, params=None):
    """Simulate a DB owner bypassing the trigger: disable it, run `sql`, re-enable it."""
    with connection.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")  # flush deferred FK checks so ALTER TABLE is allowed
        cur.execute("ALTER TABLE audit_event DISABLE TRIGGER USER")
        cur.execute(sql, params)
        cur.execute("ALTER TABLE audit_event ENABLE TRIGGER USER")


# --- chain ------------------------------------------------------------------------------

@pytest.mark.django_db
def test_events_form_a_verifiable_chain(org_a):
    evs = [make_event(org_a) for _ in range(5)]
    assert evs[0].prev_hash == GENESIS_HASH
    assert all(evs[i].prev_hash == evs[i - 1].entry_hash for i in range(1, 5))
    assert verify_chain(org_a.id) == (True, None)


@pytest.mark.django_db
def test_chains_are_independent_per_organization(org_a, org_b):
    make_event(org_a), make_event(org_b)
    assert AuditEvent.objects.get(organization=org_b).prev_hash == GENESIS_HASH


@pytest.mark.django_db
def test_tampering_is_detected_even_by_someone_who_bypasses_the_trigger(org_a):
    evs = [make_event(org_a) for _ in range(4)]
    as_table_owner("UPDATE audit_event SET outcome='DENIED' WHERE id=%s", [evs[1].id])
    assert verify_chain(org_a.id) == (False, evs[1].id)


@pytest.mark.django_db
def test_deleting_a_row_breaks_the_chain(org_a):
    evs = [make_event(org_a) for _ in range(4)]
    as_table_owner("DELETE FROM audit_event WHERE id=%s", [evs[2].id])
    ok, bad = verify_chain(org_a.id)
    assert ok is False and bad == evs[3].id


@pytest.mark.django_db
def test_a_forger_without_the_hmac_key_cannot_recompute_the_chain(org_a):
    [make_event(org_a) for _ in range(3)]
    with override_settings(AUDIT_HMAC_KEY="attacker-guess"):
        assert verify_chain(org_a.id)[0] is False


@pytest.mark.django_db(transaction=True)
def test_concurrent_writers_keep_a_single_valid_chain(org_a):
    errors = []

    def worker():
        try:
            for _ in range(5):
                make_event(org_a)
        except Exception as exc:  # pragma: no cover - reported below
            errors.append(exc)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=worker) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors
    assert AuditEvent.objects.filter(organization=org_a).count() == 40
    assert verify_chain(org_a.id) == (True, None)


# --- append-only ------------------------------------------------------------------------

@pytest.mark.django_db
def test_orm_refuses_update_and_delete(org_a):
    ev = make_event(org_a)
    ev.outcome = "DENIED"
    with pytest.raises(AuditImmutableError):
        ev.save()
    with pytest.raises(AuditImmutableError):
        ev.delete()
    with pytest.raises(AuditImmutableError):
        AuditEvent.objects.all().update(outcome="DENIED")
    with pytest.raises(AuditImmutableError):
        AuditEvent.objects.all().delete()


@pytest.mark.django_db
def test_database_trigger_refuses_raw_sql_update_and_delete(org_a):
    ev = make_event(org_a)
    for sql in ("UPDATE audit_event SET outcome='DENIED' WHERE id=%s", "DELETE FROM audit_event WHERE id=%s"):
        with pytest.raises(DatabaseError, match="append-only"):
            with transaction.atomic(), connection.cursor() as cur:
                cur.execute(sql, [ev.id])
    assert AuditEvent.objects.get(pk=ev.pk).outcome == "SUCCESS"


# --- no secrets -------------------------------------------------------------------------

def test_scrub_redacts_sensitive_keys_recursively():
    out = scrub({"password": "hunter2", "ok": "fine", "nested": {"api_token": "abc", "list": [{"Authorization": "Bearer x"}]}})
    assert out["password"] == REDACTED
    assert out["ok"] == "fine"
    assert out["nested"]["api_token"] == REDACTED
    assert out["nested"]["list"][0]["Authorization"] == REDACTED


def test_scrub_truncates_long_values_and_handles_odd_types():
    assert len(scrub({"note": "x" * 5000})["note"]) == 500
    assert scrub({"when": object()})["when"].startswith("<object")


@pytest.mark.django_db
def test_record_scrubs_metadata_before_storing(org_a):
    ev = record(
        action="EDIT", outcome="SUCCESS", organization=org_a,
        metadata={"password": "hunter2", "encryption_key": "AAAA", "title": "db prod"},
    )
    stored = AuditEvent.objects.get(pk=ev.pk).metadata
    assert stored == {"password": REDACTED, "encryption_key": REDACTED, "title": "db prod"}
    assert "hunter2" not in str(AuditEvent.objects.values())


@pytest.mark.django_db
def test_unknown_action_is_rejected(org_a):
    with pytest.raises(ValueError):
        record(action="MADE_UP", outcome="SUCCESS", organization=org_a)


@pytest.mark.django_db
def test_missing_hmac_key_fails_closed(org_a):
    from django.core.exceptions import ImproperlyConfigured

    with override_settings(AUDIT_HMAC_KEY=""), pytest.raises(ImproperlyConfigured):
        make_event(org_a)
    assert AuditEvent.objects.count() == 0


# --- request context --------------------------------------------------------------------

@pytest.mark.django_db
def test_events_capture_request_context_and_response_echoes_request_id(api, make_user, org_a):
    user = make_user(org_a, "EMPLOYEE")
    resp = api.post(
        "/api/auth/login/", {"email": user.email, "password": "Correct-Horse-Battery-9"}, format="json",
        HTTP_USER_AGENT="pytest-agent", HTTP_X_REQUEST_ID="client-chosen-id",
    )
    ev = AuditEvent.objects.get(action="LOGIN")
    assert ev.ip_address == "127.0.0.1" and ev.user_agent == "pytest-agent"
    assert ev.request_id == resp["X-Request-ID"] != "client-chosen-id"  # server-generated only
    assert ev.actor == user and ev.organization == org_a


@pytest.mark.django_db
def test_audit_list_endpoint_hides_hashes_and_supports_filters(api_as, make_user, org_a):
    admin = make_user(org_a, "PLATFORM_ADMIN")
    make_event(org_a)
    record(action="LOGOUT", outcome="SUCCESS", organization=org_a)
    rows = api_as(admin).get("/api/audit/events/?action=LOGOUT").json()["results"]
    assert [r["action"] for r in rows] == ["LOGOUT"]
    assert not {"entry_hash", "prev_hash", "metadata"} & set(rows[0])
