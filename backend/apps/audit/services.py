import hashlib
import hmac
import json
from datetime import timezone as dt_timezone

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import connection, transaction
from django.utils import timezone

from .models import AuditEvent
from .scrub import scrub

GENESIS_HASH = "0" * 64
_LOCK_NAMESPACE = 7001 << 32  # advisory-lock key space reserved for audit chains

_HASHED_FIELDS = (
    "organization_id",
    "actor_id",
    "actor_email",
    "action",
    "outcome",
    "target_type",
    "target_id",
    "reason_code",
    "ip_address",
    "user_agent",
    "device_fingerprint",
    "request_id",
    "metadata",
)


def _key() -> bytes:
    key = settings.AUDIT_HMAC_KEY
    if not key:
        raise ImproperlyConfigured("AUDIT_HMAC_KEY must be set (see .env.example).")
    return key.encode()


def _compute_hash(prev_hash: str, created_at, fields: dict) -> str:
    payload = {"created_at": created_at.astimezone(dt_timezone.utc).isoformat(), **fields}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hmac.new(_key(), f"{prev_hash}|{canonical}".encode(), hashlib.sha256).hexdigest()


def _entry_fields(obj) -> dict:
    return {name: getattr(obj, name) for name in _HASHED_FIELDS}


def client_ip(request) -> str | None:
    """Direct peer address only. `X-Forwarded-For` is client-controlled unless a trusted
    proxy overwrites it, so it must be wired in deliberately at deployment time."""
    return request.META.get("REMOTE_ADDR") if request is not None else None


def record(
    *,
    action: str,
    outcome: str,
    actor=None,
    organization=None,
    actor_email: str = "",
    target_type: str = "",
    target_id="",
    reason_code: str = "",
    metadata: dict | None = None,
    request=None,
) -> AuditEvent:
    """Append one event to the organization's hash chain.

    Concurrency: a transaction-scoped advisory lock serializes writers per chain, so two
    simultaneous events can never both link to the same predecessor.
    """
    if action not in AuditEvent.Action.values or outcome not in AuditEvent.Outcome.values:
        raise ValueError("Unknown audit action or outcome.")
    org_id = organization.pk if organization is not None else (actor.organization_id if actor is not None else None)

    with transaction.atomic():
        with connection.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(%s)", [_LOCK_NAMESPACE | (org_id or 0)])
        prev_hash = (
            AuditEvent.objects.filter(organization_id=org_id).order_by("-id").values_list("entry_hash", flat=True).first()
            or GENESIS_HASH
        )
        event = AuditEvent(
            organization_id=org_id,
            actor=actor if actor is not None and actor.pk else None,
            actor_email=(actor.email if actor is not None and actor.pk else actor_email)[:254],
            action=action,
            outcome=outcome,
            target_type=target_type[:60],
            target_id=str(target_id)[:64],
            reason_code=reason_code[:60],
            ip_address=client_ip(request),
            user_agent=(request.META.get("HTTP_USER_AGENT", "")[:300] if request is not None else ""),
            request_id=getattr(request, "request_id", "") if request is not None else "",
            metadata=scrub(metadata or {}),
            created_at=timezone.now(),
            prev_hash=prev_hash,
        )
        event.entry_hash = _compute_hash(prev_hash, event.created_at, _entry_fields(event))
        event.save()
    return event


def verify_chain(organization_id) -> tuple[bool, int | None]:
    """Recompute the chain. Returns (ok, id_of_first_bad_event_or_None)."""
    expected_prev = GENESIS_HASH
    for ev in AuditEvent.objects.filter(organization_id=organization_id).order_by("id").iterator():
        if ev.prev_hash != expected_prev:
            return False, ev.id
        if not hmac.compare_digest(ev.entry_hash, _compute_hash(ev.prev_hash, ev.created_at, _entry_fields(ev))):
            return False, ev.id
        expected_prev = ev.entry_hash
    return True, None
