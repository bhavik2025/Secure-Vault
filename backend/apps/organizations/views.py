from rest_framework.generics import RetrieveAPIView
from rest_framework.mixins import CreateModelMixin, ListModelMixin, RetrieveModelMixin, UpdateModelMixin
from rest_framework.viewsets import GenericViewSet

from apps.accounts.permissions import HasAppPermission
from apps.audit.models import AuditEvent
from apps.audit.services import record
from apps.core.scoping import OrganizationScopedMixin

from .models import Department
from .serializers import DepartmentSerializer, OrganizationSerializer


class OrganizationView(RetrieveAPIView):
    """The requester's own organization. There is no ID in the URL, so nothing to tamper with."""

    serializer_class = OrganizationSerializer
    permission_classes = [HasAppPermission("org.view")]

    def get_object(self):
        return self.request.user.organization


class DepartmentViewSet(
    OrganizationScopedMixin, CreateModelMixin, ListModelMixin, RetrieveModelMixin, UpdateModelMixin, GenericViewSet
):
    """No DELETE: departments are set INACTIVE so history and member links stay intact."""

    queryset = Department.objects.all()
    serializer_class = DepartmentSerializer

    def get_permissions(self):
        code = "departments.view" if self.action in ("list", "retrieve") else "departments.manage"
        return [HasAppPermission(code)()]

    def _audit(self, instance, reason):
        record(
            action=AuditEvent.Action.CREATE if reason == "created" else AuditEvent.Action.EDIT,
            outcome=AuditEvent.Outcome.SUCCESS,
            actor=self.request.user,
            target_type="department",
            target_id=instance.pk,
            reason_code=reason,
            metadata={"code": instance.code, "name": instance.name, "status": instance.status},
            request=self.request,
        )

    def perform_create(self, serializer):
        instance = serializer.save(organization=self.request.user.organization)
        self._audit(instance, "created")

    def perform_update(self, serializer):
        self._audit(serializer.save(), "updated")
