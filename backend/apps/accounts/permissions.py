from rest_framework.permissions import BasePermission

from apps.audit.models import AuditEvent
from apps.audit.services import record


def HasAppPermission(codename: str):
    """Build a DRF permission class requiring an application permission.

    Server-side RBAC gate: 401/403 for anonymous or inactive users (session auth already
    drops non-ACTIVE accounts), 403 + an AUTHZ_DENIED audit event for missing permission.
    """

    class _HasAppPermission(BasePermission):
        message = "You do not have permission to perform this action."

        def has_permission(self, request, view):
            user = request.user
            if not user or not user.is_authenticated:
                return False
            if user.has_app_perm(codename):
                return True
            record(
                action=AuditEvent.Action.AUTHZ_DENIED,
                outcome=AuditEvent.Outcome.DENIED,
                actor=user,
                reason_code="missing_permission",
                metadata={"required": codename, "method": request.method, "path": request.path},
                request=request,
            )
            return False

    _HasAppPermission.__name__ = f"HasAppPermission[{codename}]"
    return _HasAppPermission
