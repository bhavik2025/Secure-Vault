from drf_spectacular.utils import extend_schema
from rest_framework.decorators import action
from rest_framework.mixins import CreateModelMixin, ListModelMixin, RetrieveModelMixin, UpdateModelMixin
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from apps.accounts.permissions import HasAppPermission
from apps.audit.models import AuditEvent
from apps.audit.services import changed_fields, record
from apps.core.scoping import OrganizationScopedMixin

from .models import ServiceCatalogEntry
from .serializers import ServiceSerializer, snapshot


class ServiceViewSet(
    OrganizationScopedMixin, CreateModelMixin, ListModelMixin, RetrieveModelMixin, UpdateModelMixin, GenericViewSet
):
    """Service catalogue. Everyone can read ACTIVE entries (to pick a service); only holders of
    `services.manage` see INACTIVE ones or can write. There is deliberately no DELETE route."""

    queryset = ServiceCatalogEntry.objects.all()
    serializer_class = ServiceSerializer

    def get_permissions(self):
        code = "services.view" if self.action in ("list", "retrieve") else "services.manage"
        return [HasAppPermission(code)()]

    def get_queryset(self):
        qs = super().get_queryset()
        if not self.request.user.has_app_perm("services.manage"):
            qs = qs.filter(status=ServiceCatalogEntry.Status.ACTIVE)
        p = self.request.query_params
        if p.get("status"):
            qs = qs.filter(status=p["status"])
        if p.get("category"):
            qs = qs.filter(category=p["category"])
        if p.get("q"):
            qs = qs.filter(name__icontains=p["q"][:120])
        return qs

    def _audit(self, instance, reason, changes):
        record(
            action=AuditEvent.Action.CREATE if reason == "created" else AuditEvent.Action.EDIT,
            outcome=AuditEvent.Outcome.SUCCESS,
            actor=self.request.user,
            target_type="service",
            target_id=instance.pk,
            reason_code=reason,
            metadata={"name": instance.name, "changes": changes},
            request=self.request,
        )

    def perform_create(self, serializer):
        instance = serializer.save(organization=self.request.user.organization)
        self._audit(instance, "created", changed_fields({}, snapshot(instance)))

    def perform_update(self, serializer):
        before = snapshot(serializer.instance)
        instance = serializer.save()
        changes = changed_fields(before, snapshot(instance))
        if changes:
            self._audit(instance, "updated", changes)

    def _set_status(self, request, new_status, reason):
        instance = self.get_object()
        before = snapshot(instance)
        if instance.status != new_status:
            instance.status = new_status
            instance.save(update_fields=["status", "updated_at"])
            self._audit(instance, reason, changed_fields(before, snapshot(instance)))
        return Response(self.get_serializer(instance).data)

    @extend_schema(request=None, responses=ServiceSerializer)
    @action(detail=True, methods=["post"])
    def deactivate(self, request, pk=None):
        return self._set_status(request, ServiceCatalogEntry.Status.INACTIVE, "deactivated")

    @extend_schema(request=None, responses=ServiceSerializer)
    @action(detail=True, methods=["post"])
    def activate(self, request, pk=None):
        return self._set_status(request, ServiceCatalogEntry.Status.ACTIVE, "activated")
