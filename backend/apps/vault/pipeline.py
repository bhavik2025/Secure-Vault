"""The zero-trust security pipeline for revealing (decrypting) a secret.

    1 authenticate        DRF session authentication (before we are called)
    2 account status      only ACTIVE accounts
    3 role + permission   `vault.use` (permission class) AND ownership or an explicit grant with VIEW
    4 grant lease         grant and every ancestor: not revoked, not consumed, not expired
    5 device trust        organization policy `require_device_trust`
    6 anomaly / risk      hook (no signals exist yet; see the device module)
    7 lockdown            fresh database read; independent of any WebSocket message
    8 execute             re-verify under a row lock, decrypt, and (view-once) burn - atomically
    9 audit               REVEAL success/denied/failure, never containing the secret
   10 respond             the caller returns only the authorized payload

Failures at steps 2-7 and inside step 8 are audited as DENIED and NEVER consume a view-once grant:
the burn is the last write, in the same transaction as the decryption.

Honest scope notes: step 5 fails CLOSED when the policy requires device trust because the device module
is not built yet; step 6 is an extension point only.
"""
from dataclasses import dataclass

from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import APIException, PermissionDenied

from apps.audit.models import AuditEvent
from apps.audit.services import record
from apps.core.api_errors import (
    DecryptionFailed,
    DeviceTrustUnavailable,
    GrantConsumed,
    GrantExpired,
    GrantRevoked,
    NoAccess,
    RecordArchived,
    ViewNotGranted,
)
from apps.lockdown.gate import lockdown_gate
from apps.policies.enforcement import device_trust_required, get_effective_policy
from apps.sharing.access import Access, grant_usable, resolve_access
from apps.sharing.models import Share

from .crypto import CryptoError
from .models import Credential
from .services import unseal_for_reveal


@dataclass
class RevealResult:
    secret: str
    via: str  # "owner" | "grant"
    grant_id: int | None
    view_once: bool


def device_gate(user) -> None:
    """Step 5. If the organization requires a trusted device we cannot yet establish one, so deny."""
    if device_trust_required(get_effective_policy(user.organization_id)):
        raise DeviceTrustUnavailable()


def anomaly_gate(request, user) -> None:
    """Step 6 extension point. No risk signals are collected yet, so nothing is denied here."""
    return None


def _access_for(user, record_) -> Access:
    if isinstance(record_, Credential):
        return resolve_access(user, record_)
    if record_.organization_id != user.organization_id or record_.owner_id != user.pk:
        raise NoAccess()  # secure notes are never shared
    return Access(role="owner", can_view=True, can_edit=True, can_share=True)


def _authorize(request, user, record_) -> Access:
    if not user.is_active:  # step 2
        raise PermissionDenied("Account is not active.")
    access = _access_for(user, record_)  # steps 3-4
    if not access.can_view:
        raise ViewNotGranted()
    if record_.status != record_.Status.ACTIVE:
        raise RecordArchived()
    device_gate(user)  # step 5
    anomaly_gate(request, user)  # step 6
    lockdown_gate(user)  # step 7
    return access


def _audit(request, user, record_, outcome, reason, extra=None):
    record(
        action=AuditEvent.Action.REVEAL,
        outcome=outcome,
        actor=user,
        target_type=record_.AUDIT_TYPE,
        target_id=record_.pk,
        reason_code=reason,
        metadata=extra or {},
        request=request,
    )


def reveal(request, record_) -> RevealResult:
    """Run the pipeline for `record_` (a Credential or SecureNote) on behalf of request.user."""
    user = request.user
    try:
        access = _authorize(request, user, record_)
        return _execute(request, user, record_, access)
    except APIException as exc:
        # Reached only for refusals; nothing was consumed. (Success is audited inside _execute.)
        _audit(request, user, record_, AuditEvent.Outcome.DENIED, exc.get_codes() if isinstance(exc.get_codes(), str) else "denied")
        raise
    except CryptoError:
        _audit(request, user, record_, AuditEvent.Outcome.FAILURE, "decryption_failed")
        raise DecryptionFailed() from None


def _execute(request, user, record_, access: Access) -> RevealResult:
    grant = access.grant_for_reveal()
    with transaction.atomic():
        locked = None
        if grant is not None:
            # Serialize with revocation and with competing view-once reveals of the same grant.
            locked = Share.objects.select_for_update(of=("self",)).select_related("parent").get(pk=grant.pk)
            state = locked.status_at()
            if state == "CONSUMED":
                raise GrantConsumed()
            if state == "REVOKED":
                raise GrantRevoked()
            if state == "EXPIRED":
                raise GrantExpired()
            if not grant_usable(locked):
                raise GrantRevoked()  # an ancestor was revoked or expired meanwhile
        lockdown_gate(user)  # last-moment re-check, right before any decryption
        secret = unseal_for_reveal(record_)  # a failure here rolls back: nothing is burned
        if locked is not None and locked.is_view_once:
            locked.burned_at = timezone.now()  # the very last write, in the same transaction
            locked.save(update_fields=["burned_at"])
        _audit(
            request, user, record_, AuditEvent.Outcome.SUCCESS,
            "granted_view_once" if (locked is not None and locked.is_view_once) else ("granted" if locked else "owner"),
            {"via": "grant" if locked else "owner", "grant_id": locked.pk if locked else None,
             "view_once": bool(locked and locked.is_view_once)},
        )
    return RevealResult(
        secret=secret,
        via="grant" if locked else "owner",
        grant_id=locked.pk if locked else None,
        view_once=bool(locked and locked.is_view_once),
    )
