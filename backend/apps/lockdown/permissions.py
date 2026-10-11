from rest_framework.permissions import BasePermission

from apps.audit.models import AuditEvent
from apps.audit.services import record

from .gate import lockdown_gate
from apps.core.api_errors import LockdownActive


class NotLockedDown(BasePermission):
    """DRF permission for sensitive WRITE endpoints. Revocation endpoints deliberately do not use it:
    during an incident, taking access away must always remain possible."""

    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return True  # authentication is enforced by the other permission classes
        try:
            lockdown_gate(user)
        except LockdownActive:
            record(
                action=AuditEvent.Action.AUTHZ_DENIED,
                outcome=AuditEvent.Outcome.DENIED,
                actor=user,
                reason_code="lockdown_active",
                metadata={"method": request.method, "path": request.path},
                request=request,
            )
            raise
        return True
