"""Envelope encryption for vault secrets (AES-256-GCM). See docs/crypto.md.

Model
-----
  secret --AES-256-GCM(DEK, fresh nonce)--> payload
  DEK    --AES-256-GCM(KEK, fresh nonce)--> wrapped_dek       (KEK chosen by version)

* A new random 256-bit DEK is generated for EVERY encryption, so a DEK never encrypts two
  different values and a nonce can never repeat under the same DEK.
* Nonces are 12 random bytes from the OS CSPRNG, drawn for every single AES-GCM operation.
* Both operations bind **associated data** (purpose, organization, record UID, and for the wrapped
  DEK the KEK version). A ciphertext or wrapped key copied onto another record/field/organization
  therefore fails authentication instead of decrypting.
* The blind-index key is a separate secret and is never used for encryption.

Blob layout (payload and wrapped_dek), format version 1:

    byte 0        format version (0x01)
    bytes 1..12   nonce (12)
    bytes 13..28  GCM authentication tag (16)
    bytes 29..    ciphertext (same length as the plaintext)

This module does NOT implement a cipher; it composes the audited primitives in `cryptography`.
Python cannot reliably zeroize memory, so plaintext may linger in process memory until collected.
"""
import base64
import binascii
import hashlib
import hmac
import os
import unicodedata
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings
from django.views.decorators.debug import sensitive_variables

FORMAT_V1 = 1
KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16
HEADER_LEN = 1 + NONCE_LEN + TAG_LEN
MAX_PLAINTEXT_BYTES = 256 * 1024

PURPOSE_CREDENTIAL_PASSWORD = "credential.password"
PURPOSE_NOTE_CONTENT = "secure_note.content"
_PURPOSES = {PURPOSE_CREDENTIAL_PASSWORD, PURPOSE_NOTE_CONTENT}


class CryptoError(Exception):
    """Base class. Messages never contain key material or plaintext."""


class CryptoConfigError(CryptoError):
    """Missing or invalid key configuration. Fails closed: nothing is encrypted or decrypted."""


class UnknownKeyVersion(CryptoConfigError):
    """A record references a KEK version that is not configured."""


class DecryptionError(CryptoError):
    """Authentication failed: tampered data, wrong key, or wrong record/field context."""


class CryptoFormatError(DecryptionError):
    """The stored blob is not a well-formed v1 payload."""


@dataclass(frozen=True)
class KeyRing:
    keks: dict[int, bytes] = field(repr=False)
    active_version: int
    blind_key: bytes = field(repr=False)


@dataclass(frozen=True)
class SealedSecret:
    enc_format: int
    kek_version: int
    wrapped_dek: bytes = field(repr=False)
    payload: bytes = field(repr=False)


# --- configuration ---------------------------------------------------------------------------

def _decode_key(name: str, value: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError, TypeError):
        raise CryptoConfigError(f"{name} is not valid base64.") from None
    if len(raw) != KEY_LEN:
        raise CryptoConfigError(f"{name} must decode to exactly {KEY_LEN} bytes (got {len(raw)}).")
    return raw


def load_keyring() -> KeyRing:
    """Parse and validate key configuration. Cheap (a few base64 decodes); never cached, so a
    changed setting or rotated environment takes effect immediately and tests can override it."""
    configured = settings.VAULT_KEY_ENCRYPTION_KEYS_B64
    if not configured:
        raise CryptoConfigError("No key-encryption key is configured (set VAULT_KEK_V1 in the environment).")
    keks = {int(v): _decode_key(f"VAULT_KEK_V{v}", b64) for v, b64 in configured.items()}
    active = settings.VAULT_ACTIVE_KEK_VERSION
    if active not in keks:
        raise CryptoConfigError(f"Active KEK version {active} is not configured.")
    if not settings.VAULT_BLIND_INDEX_KEY_B64:
        raise CryptoConfigError("VAULT_BLIND_INDEX_KEY is not configured.")
    blind = _decode_key("VAULT_BLIND_INDEX_KEY", settings.VAULT_BLIND_INDEX_KEY_B64)

    values = list(keks.values())
    if len({bytes(v) for v in values}) != len(values):
        raise CryptoConfigError("Key-encryption keys for different versions must be distinct.")
    if any(hmac.compare_digest(blind, k) for k in values):
        raise CryptoConfigError("VAULT_BLIND_INDEX_KEY must differ from every key-encryption key.")
    return KeyRing(keks=keks, active_version=active, blind_key=blind)


# --- primitives ------------------------------------------------------------------------------

def _new_nonce() -> bytes:
    """Single choke point for nonce generation: 12 bytes from the OS CSPRNG, every time."""
    return os.urandom(NONCE_LEN)


def _new_dek() -> bytes:
    """A fresh 256-bit key from the same single entropy source (OS CSPRNG) as the nonces."""
    return os.urandom(KEY_LEN)


def _aead_seal(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = _new_nonce()
    sealed = AESGCM(key).encrypt(nonce, plaintext, aad)  # ciphertext || tag
    ciphertext, tag = sealed[:-TAG_LEN], sealed[-TAG_LEN:]
    return bytes([FORMAT_V1]) + nonce + tag + ciphertext


def _aead_open(key: bytes, blob: bytes, aad: bytes) -> bytes:
    blob = bytes(blob)
    if len(blob) < HEADER_LEN or blob[0] != FORMAT_V1:
        raise CryptoFormatError("Stored value is not a valid v1 encrypted payload.")
    nonce = blob[1 : 1 + NONCE_LEN]
    tag = blob[1 + NONCE_LEN : HEADER_LEN]
    ciphertext = blob[HEADER_LEN:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext + tag, aad)
    except InvalidTag:
        raise DecryptionError("Decryption failed: data was altered, or the wrong key or context was used.") from None


def _aad_payload(purpose: str, org_id: int, uid) -> bytes:
    return f"SV1|payload|{purpose}|{org_id}|{uid}".encode()


def _aad_dek(purpose: str, org_id: int, uid, kek_version: int) -> bytes:
    return f"SV1|dek|{purpose}|{org_id}|{uid}|kek{kek_version}".encode()


def _check_purpose(purpose: str) -> None:
    if purpose not in _PURPOSES:
        raise ValueError("Unknown encryption purpose.")


# --- public API ------------------------------------------------------------------------------

@sensitive_variables()
def encrypt_secret(plaintext: str | bytes, *, purpose: str, org_id: int, uid) -> SealedSecret:
    """Encrypt under a brand-new DEK and wrap that DEK with the ACTIVE KEK."""
    _check_purpose(purpose)
    data = plaintext.encode("utf-8") if isinstance(plaintext, str) else bytes(plaintext)
    if not data:
        raise ValueError("Refusing to encrypt an empty secret.")
    if len(data) > MAX_PLAINTEXT_BYTES:
        raise ValueError("Secret is too large.")
    ring = load_keyring()
    dek = _new_dek()
    payload = _aead_seal(dek, data, _aad_payload(purpose, org_id, uid))
    wrapped = _aead_seal(ring.keks[ring.active_version], dek, _aad_dek(purpose, org_id, uid, ring.active_version))
    return SealedSecret(FORMAT_V1, ring.active_version, wrapped, payload)


def _unwrap_dek(sealed: SealedSecret, ring: KeyRing, purpose: str, org_id: int, uid) -> bytes:
    kek = ring.keks.get(sealed.kek_version)
    if kek is None:
        raise UnknownKeyVersion(f"KEK version {sealed.kek_version} is not configured.")
    return _aead_open(kek, sealed.wrapped_dek, _aad_dek(purpose, org_id, uid, sealed.kek_version))


@sensitive_variables()
def decrypt_secret(sealed: SealedSecret, *, purpose: str, org_id: int, uid) -> str:
    """Return the plaintext. INTERNAL: only the authorized reveal pipeline (a later phase) may call
    this; no API route exposes it. Raises DecryptionError on any authentication failure."""
    _check_purpose(purpose)
    if sealed.enc_format != FORMAT_V1:
        raise CryptoFormatError("Unsupported encryption format version.")
    ring = load_keyring()
    dek = _unwrap_dek(sealed, ring, purpose, org_id, uid)
    return _aead_open(dek, sealed.payload, _aad_payload(purpose, org_id, uid)).decode("utf-8")


@sensitive_variables()
def rewrap_dek(sealed: SealedSecret, *, purpose: str, org_id: int, uid) -> SealedSecret:
    """Re-wrap the DEK under the ACTIVE KEK. The payload is untouched (the secret is never decrypted),
    so KEK rotation is cheap and never exposes plaintext."""
    _check_purpose(purpose)
    ring = load_keyring()
    dek = _unwrap_dek(sealed, ring, purpose, org_id, uid)
    wrapped = _aead_seal(ring.keks[ring.active_version], dek, _aad_dek(purpose, org_id, uid, ring.active_version))
    return SealedSecret(sealed.enc_format, ring.active_version, wrapped, bytes(sealed.payload))


@sensitive_variables()
def blind_index(password: str, org_id: int) -> str:
    """Deterministic keyed fingerprint (HMAC-SHA-256) for equality / reuse detection.

    Keyed with the dedicated blind-index key, scoped per organization, NFC-normalised. It never
    touches a KEK. See docs/crypto.md for its limits: equal passwords yield equal indexes, so it leaks
    equality to anyone who can read the table; and a stolen index key allows offline guessing.
    """
    key = load_keyring().blind_key
    message = f"SV1|blind|{PURPOSE_CREDENTIAL_PASSWORD}|{org_id}|".encode() + unicodedata.normalize("NFC", password).encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()
