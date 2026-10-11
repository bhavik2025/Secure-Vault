import base64
from io import StringIO

import pytest
from django.core.management import CommandError, call_command

from apps.vault.models import Credential, SecureNote
from apps.vault.services import unseal_for_reveal

from .conftest import GOOD

pytestmark = pytest.mark.django_db


def run(*args):
    out, err = StringIO(), StringIO()
    call_command(*args, stdout=out, stderr=err)
    return out.getvalue(), err.getvalue()


def test_generate_vault_keys_emits_valid_distinct_32_byte_keys():
    out, err = run("generate_vault_keys")
    cfg = dict(line.split("=", 1) for line in out.strip().splitlines())
    assert set(cfg) == {"VAULT_KEK_V1", "VAULT_KEK_ACTIVE_VERSION", "VAULT_BLIND_INDEX_KEY"}
    kek, blind = (base64.b64decode(cfg[k], validate=True) for k in ("VAULT_KEK_V1", "VAULT_BLIND_INDEX_KEY"))
    assert len(kek) == 32 and len(blind) == 32 and kek != blind
    assert "SECRETS" in err  # the warning goes to stderr, never mixed into the values
    again = dict(line.split("=", 1) for line in run("generate_vault_keys")[0].strip().splitlines())
    assert again["VAULT_KEK_V1"] != cfg["VAULT_KEK_V1"]  # fresh randomness each run


def test_generate_vault_keys_for_rotation_emits_only_a_new_kek():
    out, _ = run("generate_vault_keys", "--kek-version", "3")
    assert out.startswith("VAULT_KEK_V3=") and len(out.strip().splitlines()) == 1


@pytest.fixture
def vault_rows(emp_client):
    cid = emp_client.post("/api/vault/credentials/", {"title": "Cred", "password": GOOD}, format="json").json()["id"]
    nid = emp_client.post("/api/vault/notes/", {"title": "Note", "content": "note secret"}, format="json").json()["id"]
    return Credential.objects.get(pk=cid), SecureNote.objects.get(pk=nid)


def test_kek_rotation_rewraps_without_changing_payloads(settings, vault_rows):
    cred, note = vault_rows
    payloads = (bytes(cred.password_enc), bytes(note.content_enc))
    settings.VAULT_ACTIVE_KEK_VERSION = 2

    assert "would re-wrap 2 of 2" in run("rewrap_vault_keys", "--dry-run")[0]
    assert Credential.objects.get(pk=cred.pk).kek_version == 1  # dry run changed nothing

    assert "re-wrapped 2 of 2" in run("rewrap_vault_keys")[0]
    cred, note = Credential.objects.get(pk=cred.pk), SecureNote.objects.get(pk=note.pk)
    assert cred.kek_version == note.kek_version == 2
    assert (bytes(cred.password_enc), bytes(note.content_enc)) == payloads  # secrets never re-encrypted
    assert unseal_for_reveal(cred) == GOOD and unseal_for_reveal(note) == "note secret"
    assert "re-wrapped 0 of 0" in run("rewrap_vault_keys")[0]  # idempotent

    settings.VAULT_KEY_ENCRYPTION_KEYS_B64 = {2: settings.VAULT_KEY_ENCRYPTION_KEYS_B64[2]}  # retire KEK v1
    assert unseal_for_reveal(Credential.objects.get(pk=cred.pk)) == GOOD


def test_rewrap_fails_loudly_if_the_old_kek_was_already_removed(settings, vault_rows):
    settings.VAULT_KEY_ENCRYPTION_KEYS_B64 = {2: settings.VAULT_KEY_ENCRYPTION_KEYS_B64[2]}
    settings.VAULT_ACTIVE_KEK_VERSION = 2
    with pytest.raises(CommandError, match="could not be re-wrapped"):
        run("rewrap_vault_keys")
    assert Credential.objects.get(pk=vault_rows[0].pk).kek_version == 1  # untouched


def test_rewrap_refuses_to_run_with_broken_configuration(settings):
    settings.VAULT_KEY_ENCRYPTION_KEYS_B64 = {}
    with pytest.raises(CommandError):
        run("rewrap_vault_keys")
