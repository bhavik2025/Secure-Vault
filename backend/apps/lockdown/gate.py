from django.db.models import Q

from apps.core.api_errors import LockdownActive

from .models import LockdownState


def active_lockdown(user):
    """The newest ACTIVE lockdown that applies to this user (organization-wide, or aimed at them)."""
    return (
        LockdownState.objects.filter(organization_id=user.organization_id, is_active=True)
        .filter(Q(scope=LockdownState.Scope.GLOBAL) | Q(scope=LockdownState.Scope.USER, target_user_id=user.pk))
        .order_by("-triggered_at")
        .first()
    )


def lockdown_gate(user) -> None:
    """Pipeline step 7. Raises LockdownActive (HTTP 423). Always a fresh database read: there is no
    cache and no dependence on a WebSocket message having reached anyone."""
    if active_lockdown(user) is not None:
        raise LockdownActive()
