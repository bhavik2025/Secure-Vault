from rest_framework.generics import ListAPIView

from apps.accounts.permissions import HasAppPermission
from apps.core.scoping import OrganizationScopedMixin

from .models import AuditEvent
from .serializers import AuditEventSerializer


class AuditEventListView(OrganizationScopedMixin, ListAPIView):
    """Read-only, organization-scoped audit trail. Newest first."""

    serializer_class = AuditEventSerializer
    permission_classes = [HasAppPermission("audit.view")]
    queryset = AuditEvent.objects.order_by("-id")

    def get_queryset(self):
        qs = super().get_queryset()
        for param in ("action", "outcome"):
            value = self.request.query_params.get(param)
            if value:
                qs = qs.filter(**{param: value})
        return qs
