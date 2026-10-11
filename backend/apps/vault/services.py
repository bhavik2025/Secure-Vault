"""Vault operations that touch plaintext. Everything here is decorated so the Django debug page
never shows plaintext in frame locals."""
from django.utils import timezone
from django.views.decorators.debug import sensitive_variables

from .crypto import blind_index, decrypt_secret, encrypt_secret
from .models import Credential, SecureNote
from .passwords import estimate_strength


def _seal(record, plaintext: str):
    record.apply_sealed(
        encrypt_secret(plaintext, purpose=record.PURPOSE, org_id=record.organization_id, uid=record.uid)
    )


@sensitive_variables()
def seal_password(credential: Credential, plaintext: str) -> None:
    """Encrypt (new DEK, new nonces), refresh the blind index, entropy estimate and change time.
    Does not save."""
    _seal(credential, plaintext)
    credential.blind_index = blind_index(plaintext, credential.organization_id)
    credential.entropy_bits = estimate_strength(plaintext).bits
    credential.password_changed_at = timezone.now()


@sensitive_variables()
def seal_note_content(note: SecureNote, plaintext: str) -> None:
    _seal(note, plaintext)


@sensitive_variables()
def unseal_for_reveal(record) -> str:
    """INTERNAL. Returns plaintext. The only intended caller is the authorized reveal pipeline
    (authorization + device trust + anomaly + lockdown + audit), which is built in a later phase.
    Nothing in the HTTP layer calls this."""
    return decrypt_secret(record.sealed(), purpose=record.PURPOSE, org_id=record.organization_id, uid=record.uid)
