from django.db import transaction

from apps.audit.models import AuditEvent
from apps.audit.services import record

from .models import SecurityPolicy

TRACKED_FIELDS = ("name", "min_length", "require_symbols", "max_age_days", "allow_view_once", "require_device_trust")


def snapshot(policy: SecurityPolicy) -> dict:
    return {f: getattr(policy, f) for f in TRACKED_FIELDS}


def ensure_default_policy(organization) -> SecurityPolicy:
    """Give an organization its initial active policy (idempotent)."""
    existing = SecurityPolicy.objects.filter(organization=organization, is_active=True).first()
    if existing:
        return existing
    return SecurityPolicy.objects.create(organization=organization, name="Default Policy", is_active=True)


@transaction.atomic
def activate_policy(*, policy: SecurityPolicy, actor, request=None) -> SecurityPolicy:
    """Make `policy` the single active policy. Locks the organization's policy rows first so two
    concurrent activations serialize; the partial unique index is the final backstop."""
    siblings = list(SecurityPolicy.objects.select_for_update().filter(organization_id=policy.organization_id))
    previous = next((p for p in siblings if p.is_active and p.pk != policy.pk), None)
    if policy.is_active:
        return policy
    if previous:
        SecurityPolicy.objects.filter(pk=previous.pk).update(is_active=False)  # free the slot first
    policy.is_active = True
    policy.updated_by = actor
    policy.save(update_fields=["is_active", "updated_by", "updated_at"])
    record(
        action=AuditEvent.Action.POLICY_CHANGE,
        outcome=AuditEvent.Outcome.SUCCESS,
        actor=actor,
        target_type="security_policy",
        target_id=policy.pk,
        reason_code="activated",
        metadata={"name": policy.name, "previous_active": previous.name if previous else None},
        request=request,
    )
    return policy
