import base64
import os
import uuid
from dataclasses import replace

import pytest

from apps.vault import crypto
from apps.vault.checks import vault_key_configuration
from apps.vault.crypto import (
    HEADER_LEN,
    PURPOSE_CREDENTIAL_PASSWORD as CRED,
    PURPOSE_NOTE_CONTENT as NOTE,
    CryptoConfigError,
    CryptoFormatError,
    DecryptionError,
    UnknownKeyVersion,
    blind_index,
    decrypt_secret,
    encrypt_secret,
    load_keyring,
    rewrap_dek,
)

ORG, UID = 7, uuid.UUID(int=1)
PT = "s3cret-Value!"


def enc(pt=PT, purpose=CRED, org=ORG, uid=UID):
    return encrypt_secret(pt, purpose=purpose, org_id=org, uid=uid)


def dec(sealed, purpose=CRED, org=ORG, uid=UID):
    return decrypt_secret(sealed, purpose=purpose, org_id=org, uid=uid)


def b64(n: int) -> str:
    return base64.b64encode(bytes([n]) * 32).decode()


def flip(blob: bytes, index: int) -> bytes:
    out = bytearray(blob)
    out[index] ^= 0x01
    return bytes(out)


# --- round trip and format ---------------------------------------------------------------

@pytest.mark.parametrize("plaintext", [PT, "pässwörd-🔐-密码", "x", "line1\nline2\ttab", "a" * 10_000])
def test_round_trip(plaintext):
    assert dec(enc(plaintext)) == plaintext


def test_blob_layout_is_the_documented_v1_format():
    s = enc(PT)
    assert s.enc_format == 1 and s.kek_version == 1
    assert s.payload[0] == 1 and len(s.payload) == HEADER_LEN + len(PT.encode())
    assert s.wrapped_dek[0] == 1 and len(s.wrapped_dek) == HEADER_LEN + 32  # 61 bytes: version+nonce+tag+DEK


def test_plaintext_is_not_visible_in_any_stored_bytes():
    s = enc(PT)
    assert PT.encode() not in s.payload + s.wrapped_dek


# --- nonces and DEKs -----------------------------------------------------------------------

def test_same_plaintext_encrypts_differently_every_time():
    a, b = enc(), enc()
    assert a.payload != b.payload and a.wrapped_dek != b.wrapped_dek


def test_nonces_are_12_bytes_and_never_repeat():
    nonces = set()
    for _ in range(3000):
        s = enc()
        nonces.add(s.payload[1:13])
        nonces.add(s.wrapped_dek[1:13])
    assert len(nonces) == 6000  # every AES-GCM operation used a distinct 12-byte nonce


def test_nonces_and_dek_come_from_the_os_csprng(monkeypatch):
    sizes = []
    real = os.urandom
    monkeypatch.setattr(os, "urandom", lambda n: (sizes.append(n), real(n))[1])
    enc()
    assert sizes.count(12) == 2  # one nonce for the payload, one for the DEK wrap
    assert sizes.count(32) == 1  # exactly one fresh 256-bit DEK


def test_every_encryption_uses_a_new_dek():
    ring = load_keyring()
    deks = {crypto._unwrap_dek(enc(), ring, CRED, ORG, UID) for _ in range(50)}
    assert len(deks) == 50 and all(len(d) == 32 for d in deks)


# --- tampering -----------------------------------------------------------------------------

@pytest.mark.parametrize("index", [0, 1, 6, 12, 13, 20, 28, HEADER_LEN, HEADER_LEN + 5])  # version, nonce, tag, ciphertext
def test_any_flipped_bit_in_payload_is_rejected(index):
    s = enc()
    with pytest.raises(DecryptionError):
        dec(replace(s, payload=flip(s.payload, index)))


@pytest.mark.parametrize("index", [0, 1, 12, 13, 28, HEADER_LEN, HEADER_LEN + 31])
def test_any_flipped_bit_in_wrapped_dek_is_rejected(index):
    s = enc()
    with pytest.raises(DecryptionError):
        dec(replace(s, wrapped_dek=flip(s.wrapped_dek, index)))


def test_tampered_authentication_tag_is_rejected_specifically():
    s = enc()
    bad_tag = s.payload[:13] + bytes(16) + s.payload[29:]
    with pytest.raises(DecryptionError):
        dec(replace(s, payload=bad_tag))


@pytest.mark.parametrize("mutate", [lambda b: b[:-1], lambda b: b + b"\x00", lambda b: b[:10], lambda b: b"", lambda b: b"\x02" + b[1:]])
def test_truncated_extended_or_wrong_version_blobs_are_rejected(mutate):
    s = enc()
    with pytest.raises(DecryptionError):
        dec(replace(s, payload=mutate(s.payload)))


def test_short_or_wrong_version_blob_reports_a_format_error():
    s = enc()
    with pytest.raises(CryptoFormatError):
        dec(replace(s, payload=b"\x01short"))


def test_unsupported_format_version_field_is_rejected():
    with pytest.raises(CryptoFormatError):
        dec(replace(enc(), enc_format=9))


# --- context binding (associated data) ------------------------------------------------------

@pytest.mark.parametrize(
    "kwargs", [{"org": ORG + 1}, {"uid": uuid.UUID(int=2)}, {"purpose": NOTE}], ids=["other-org", "other-record", "other-field"]
)
def test_ciphertext_cannot_be_decrypted_in_a_different_context(kwargs):
    with pytest.raises(DecryptionError):
        dec(enc(), **kwargs)


def test_payload_authentication_is_bound_to_its_context_independently_of_the_wrapped_key():
    """Layered binding: even with the correct DEK in hand, the payload itself refuses a foreign
    organization, record or field. (The wrapped DEK binds the same context one layer up.)"""
    s = enc()
    dek = crypto._unwrap_dek(s, load_keyring(), CRED, ORG, UID)
    assert crypto._aead_open(dek, s.payload, crypto._aad_payload(CRED, ORG, UID)) == PT.encode()
    for aad in (
        crypto._aad_payload(CRED, ORG + 1, UID),
        crypto._aad_payload(CRED, ORG, uuid.UUID(int=2)),
        crypto._aad_payload(NOTE, ORG, UID),
        b"",
    ):
        with pytest.raises(DecryptionError):
            crypto._aead_open(dek, s.payload, aad)


def test_wrapped_dek_is_bound_to_context_and_kek_version_independently_of_the_payload():
    s = enc()
    kek = load_keyring().keks[1]
    good = crypto._aad_dek(CRED, ORG, UID, 1)
    assert len(crypto._aead_open(kek, s.wrapped_dek, good)) == 32
    for aad in (
        crypto._aad_dek(CRED, ORG + 1, UID, 1),
        crypto._aad_dek(CRED, ORG, uuid.UUID(int=2), 1),
        crypto._aad_dek(NOTE, ORG, UID, 1),
        crypto._aad_dek(CRED, ORG, UID, 2),  # version-downgrade/upgrade confusion
        b"",
    ):
        with pytest.raises(DecryptionError):
            crypto._aead_open(kek, s.wrapped_dek, aad)


def test_wrapped_dek_swapped_between_records_is_rejected():
    a, b = enc("first", uid=uuid.UUID(int=10)), enc("second", uid=uuid.UUID(int=11))
    with pytest.raises(DecryptionError):
        dec(replace(a, wrapped_dek=b.wrapped_dek), uid=uuid.UUID(int=10))


def test_payload_and_wrapped_dek_from_different_secrets_do_not_combine():
    a, b = enc("first"), enc("second")  # same context, different DEKs
    with pytest.raises(DecryptionError):
        dec(replace(a, wrapped_dek=b.wrapped_dek))


# --- key wrapping / KEKs --------------------------------------------------------------------

def test_wrapped_dek_is_bound_to_its_kek_version_and_key(settings):
    s = enc()
    settings.VAULT_KEY_ENCRYPTION_KEYS_B64 = {1: b64(0x61)}  # same version number, different key
    with pytest.raises(DecryptionError):
        dec(s)


def test_record_referencing_an_unconfigured_kek_version_fails_closed(settings):
    s = enc()
    settings.VAULT_KEY_ENCRYPTION_KEYS_B64 = {2: settings.VAULT_KEY_ENCRYPTION_KEYS_B64[2]}
    settings.VAULT_ACTIVE_KEK_VERSION = 2
    with pytest.raises(UnknownKeyVersion):
        dec(s)


def test_new_data_uses_the_active_kek_version(settings):
    settings.VAULT_ACTIVE_KEK_VERSION = 2
    assert enc().kek_version == 2


def test_rewrap_moves_the_dek_to_the_new_kek_without_touching_the_payload(settings):
    old = enc()
    settings.VAULT_ACTIVE_KEK_VERSION = 2
    new = rewrap_dek(old, purpose=CRED, org_id=ORG, uid=UID)
    assert new.kek_version == 2 and new.payload == old.payload and new.wrapped_dek != old.wrapped_dek
    assert dec(new) == PT
    settings.VAULT_KEY_ENCRYPTION_KEYS_B64 = {2: settings.VAULT_KEY_ENCRYPTION_KEYS_B64[2]}  # retire KEK v1
    assert dec(new) == PT
    with pytest.raises(UnknownKeyVersion):
        dec(old)


def test_rewrap_rejects_a_tampered_wrapped_dek():
    s = enc()
    with pytest.raises(DecryptionError):
        rewrap_dek(replace(s, wrapped_dek=flip(s.wrapped_dek, 20)), purpose=CRED, org_id=ORG, uid=UID)


# --- key separation ---------------------------------------------------------------------------

def test_changing_the_kek_does_not_change_blind_indexes_and_vice_versa(settings):
    s, idx = enc(), blind_index(PT, ORG)
    settings.VAULT_KEY_ENCRYPTION_KEYS_B64 = {**settings.VAULT_KEY_ENCRYPTION_KEYS_B64, 3: b64(0x33)}
    settings.VAULT_ACTIVE_KEK_VERSION = 3
    assert blind_index(PT, ORG) == idx  # KEKs are not involved in the blind index
    settings.VAULT_ACTIVE_KEK_VERSION = 1
    settings.VAULT_BLIND_INDEX_KEY_B64 = b64(0x44)
    assert blind_index(PT, ORG) != idx
    assert dec(s) == PT  # the blind-index key is not involved in encryption


def test_blind_index_key_must_differ_from_every_kek(settings):
    settings.VAULT_BLIND_INDEX_KEY_B64 = settings.VAULT_KEY_ENCRYPTION_KEYS_B64[2]
    with pytest.raises(CryptoConfigError, match="must differ"):
        load_keyring()


def test_kek_versions_must_be_distinct_keys(settings):
    settings.VAULT_KEY_ENCRYPTION_KEYS_B64 = {1: b64(0x55), 2: b64(0x55)}
    with pytest.raises(CryptoConfigError, match="distinct"):
        load_keyring()


# --- blind index ------------------------------------------------------------------------------------

def test_blind_index_is_deterministic_hex_and_input_sensitive():
    idx = blind_index(PT, ORG)
    assert idx == blind_index(PT, ORG) and len(idx) == 64 and int(idx, 16) >= 0
    assert idx != blind_index(PT + "x", ORG)
    assert idx != blind_index(PT.upper(), ORG)  # case-sensitive: exact equality only


def test_blind_index_is_scoped_per_organization():
    assert blind_index(PT, 1) != blind_index(PT, 2)


def test_blind_index_normalizes_unicode():
    assert blind_index("café", ORG) == blind_index("café", ORG)


# --- misconfiguration fails closed -------------------------------------------------------------------

BAD_CONFIGS = {
    "no-kek": {"VAULT_KEY_ENCRYPTION_KEYS_B64": {}},
    "kek-not-base64": {"VAULT_KEY_ENCRYPTION_KEYS_B64": {1: "this is not base64!!"}},
    "kek-too-short": {"VAULT_KEY_ENCRYPTION_KEYS_B64": {1: base64.b64encode(b"x" * 16).decode()}},
    "kek-too-long": {"VAULT_KEY_ENCRYPTION_KEYS_B64": {1: base64.b64encode(b"x" * 48).decode()}},
    "active-version-missing": {"VAULT_ACTIVE_KEK_VERSION": 9},
    "no-blind-key": {"VAULT_BLIND_INDEX_KEY_B64": ""},
    "blind-not-base64": {"VAULT_BLIND_INDEX_KEY_B64": "@@@@"},
    "blind-too-short": {"VAULT_BLIND_INDEX_KEY_B64": base64.b64encode(b"y" * 8).decode()},
}


@pytest.mark.parametrize("name", BAD_CONFIGS)
def test_bad_key_configuration_fails_closed_without_leaking_material(settings, name):
    for key, value in BAD_CONFIGS[name].items():
        setattr(settings, key, value)
    with pytest.raises(CryptoConfigError) as exc:
        enc()
    with pytest.raises(CryptoConfigError):
        blind_index(PT, ORG)
    leaked = [str(v) for cfg in BAD_CONFIGS[name].values() for v in (cfg.values() if isinstance(cfg, dict) else [cfg]) if v]
    assert not any(secret in str(exc.value) for secret in leaked if len(str(secret)) > 6)


def test_decrypt_also_fails_closed_when_misconfigured(settings):
    s = enc()
    settings.VAULT_KEY_ENCRYPTION_KEYS_B64 = {}
    with pytest.raises(CryptoConfigError):
        dec(s)


@pytest.mark.parametrize("pt", ["", b"", None])
def test_empty_secret_is_refused(pt):
    with pytest.raises((ValueError, TypeError)):
        enc(pt)


def test_oversized_secret_and_unknown_purpose_are_refused():
    with pytest.raises(ValueError):
        enc("x" * (crypto.MAX_PLAINTEXT_BYTES + 1))
    with pytest.raises(ValueError):
        enc(purpose="something.else")


# --- startup check ----------------------------------------------------------------------------------------

def test_system_check_ok_warning_and_error(settings):
    assert vault_key_configuration(None) == []
    settings.VAULT_ACTIVE_KEK_VERSION = 9
    errors = vault_key_configuration(None)
    assert [e.id for e in errors] == ["vault.E001"]
    settings.VAULT_KEY_ENCRYPTION_KEYS_B64 = {}
    settings.VAULT_BLIND_INDEX_KEY_B64 = ""
    assert [w.id for w in vault_key_configuration(None)] == ["vault.W001"]


def test_key_material_is_not_in_reprs():
    ring, sealed = load_keyring(), enc()
    assert "test-kek" not in repr(ring) and repr(sealed.payload) not in repr(sealed)
    assert "keks" not in repr(ring) and "payload" not in repr(sealed)


def test_plaintext_handling_functions_hide_their_locals_from_debug_pages():
    enc()
    assert encrypt_secret.sensitive_variables == "__ALL__"
