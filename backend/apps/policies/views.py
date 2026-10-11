from django.db import transaction
from drf_spectacular.utils import extend_schema
from rest_framework.decorators import action
from rest_framework.mixins import CreateModelMixin, ListModelMixin, RetrieveModelMixin, UpdateModelMixin
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from apps.accounts.permissions import HasAppPermission
from apps.audit.models import AuditEvent
from apps.audit.services import changed_fields, record
from apps.core.scoping import OrganizationScopedMixin

from .enforcement import get_effective_policy
from .models import SecurityPolicy
from .serializers import EffectivePolicySerializer, SecurityPolicySerializer
from .services import activate_policy, snapshot

_READ_ACTIONS = ("list", "retrieve")


class SecurityPolicyViewSet(
    OrganizationScopedMixin, CreateModelMixin, ListModelMixin, RetrieveModelMixin, UpdateModelMixin, GenericViewSet
):
    """No DELETE: policies are referenced by audit history. Switch the active one instead."""

    queryset = SecurityPolicy.objects.all()
    serializer_class = SecurityPolicySerializer

    def get_permissions(self):
        if self.action == "active":
            code = "org.view"  # every employee may read the rules they must follow
        elif self.action in _READ_ACTIONS:
            code = "policies.view"
        else:
            code = "policies.manage"
        return [HasAppPermission(code)()]

    def _audit(self, policy, reason, changes):
        record(
            action=AuditEvent.Action.POLICY_CHANGE,
            outcome=AuditEvent.Outcome.SUCCESS,
            actor=self.request.user,
            target_type="security_policy",
            target_id=policy.pk,
            reason_code=reason,
            metadata={"name": policy.name, "active": policy.is_active, "changes": changes},
            request=self.request,
        )

    @transaction.atomic
    def perform_create(self, serializer):
        org = self.request.user.organization
        has_active = SecurityPolicy.objects.filter(organization=org, is_active=True).exists()
        policy = serializer.save(
            organization=org, created_by=self.request.user, updated_by=self.request.user, is_active=not has_active
        )
        self._audit(policy, "created", changed_fields({}, snapshot(policy)))

    @transaction.atomic
    def perform_update(self, serializer):
        before = snapshot(serializer.instance)
        policy = serializer.save(updated_by=self.request.user)
        changes = changed_fields(before, snapshot(policy))
        if changes:
            self._audit(policy, "updated", changes)

    @extend_schema(request=None, responses=SecurityPolicySerializer)
    @action(detail=True, methods=["post"])
    def activate(self, request, pk=None):
        policy = activate_policy(policy=self.get_object(), actor=request.user, request=request)
        return Response(self.get_serializer(policy).data)

    @extend_schema(request=None, responses=EffectivePolicySerializer)
    @action(detail=False, methods=["get"])
    def active(self, request):
        return Response(EffectivePolicySerializer(get_effective_policy(request.user.organization_id)).data)
