from io import StringIO

import pytest
from django.core.management import CommandError, call_command

from apps.accounts.models import User
from apps.organizations.models import Organization
from apps.vault.models import Credential, SecureNote
from apps.vault.services import unseal_for_reveal

pytestmark = pytest.mark.django_db
PW = "Demo-Passw0rd!x"


def run(monkeypatch=None, password=None):
    if monkeypatch is not None:
        if password:
            monkeypatch.setenv("SECUREVAULT_DEMO_PASSWORD", password)
        else:
            monkeypatch.delenv("SECUREVAULT_DEMO_PASSWORD", raising=False)
    out = StringIO()
    call_command("seed_demo", stdout=out)
    return out.getvalue()


def test_refuses_to_run_outside_development(settings):
    settings.DEBUG = False
    with pytest.raises(CommandError, match="DEBUG=True"):
        call_command("seed_demo", stdout=StringIO())
    assert not Organization.objects.filter(slug="demo").exists()


def test_creates_one_user_per_role_with_encrypted_sample_data(settings, monkeypatch):
    settings.DEBUG = True
    out = run(monkeypatch, PW)
    org = Organization.objects.get(slug="demo")
    users = {u.email: u for u in User.objects.filter(organization=org)}
    assert set(users) == {"admin@demo.example", "security@demo.example", "manager@demo.example", "alice@demo.example", "bob@demo.example"}
    assert users["admin@demo.example"].has_app_perm("users.manage")
    assert users["manager@demo.example"].has_app_perm("requests.approve")
    assert users["alice@demo.example"].department == users["manager@demo.example"].department
    assert all(u.check_password(PW) and u.status == "ACTIVE" for u in users.values())
    assert PW not in out  # a supplied password is never echoed

    creds = Credential.objects.filter(organization=org)
    assert creds.count() == 4 and SecureNote.objects.filter(organization=org).count() == 1
    sample = creds.first()
    secret = unseal_for_reveal(sample)
    assert len(secret) == 20 and secret not in out  # random, never printed
    assert bytes(sample.password_enc)[0] == 1


def test_rerunning_is_idempotent_and_resets_the_password(settings, monkeypatch):
    settings.DEBUG = True
    run(monkeypatch, PW)
    run(monkeypatch, "Another-Passw0rd!")
    org = Organization.objects.get(slug="demo")
    assert User.objects.filter(organization=org).count() == 5
    assert Credential.objects.filter(organization=org).count() == 4
    assert User.objects.get(email="bob@demo.example").check_password("Another-Passw0rd!")


def test_generated_password_is_printed_once_and_works(settings, monkeypatch):
    settings.DEBUG = True
    out = run(monkeypatch, None)
    line = next(l for l in out.splitlines() if "shown once" in l)
    password = line.rsplit(": ", 1)[1].strip()
    assert User.objects.get(email="alice@demo.example").check_password(password)


def test_rejects_a_weak_supplied_password(settings, monkeypatch):
    settings.DEBUG = True
    with pytest.raises(CommandError, match="not acceptable"):
        run(monkeypatch, "short")
    assert not Organization.objects.filter(slug="demo").exists()


def test_never_touches_users_of_another_organization(settings, monkeypatch, make_user, org_a):
    settings.DEBUG = True
    make_user(org_a, "EMPLOYEE", email="alice@demo.example")
    with pytest.raises(CommandError, match="another organization"):
        run(monkeypatch, PW)
    assert not User.objects.get(email="alice@demo.example").check_password(PW)
    assert not Organization.objects.filter(slug="demo").exists()  # rolled back as a whole
