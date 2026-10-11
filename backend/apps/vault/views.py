from datetime import timedelta

from django.db.models import Q
from django.utils import timezone
from django.views.decorators.debug import sensitive_variables
from drf_spectacular.utils import extend_schema
from rest_framework.decorators import action
from rest_framework.mixins import CreateModelMixin, ListModelMixin, RetrieveModelMixin, UpdateModelMixin
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet

from apps.accounts.permissions import HasAppPermission
from apps.audit.models import AuditEvent
from apps.audit.services import changed_fields, record
from apps.core.api_errors import EditNotGranted, NoAccess
from apps.core.exceptions import PolicyViolation
from apps.core.scoping import OrganizationScopedMixin
from apps.lockdown.permissions import NotLockedDown
from apps.policies.enforcement import check_password_rules, get_effective_policy
from apps.sharing.access import resolve_access

from . import pipeline
from .models import Credential, EncryptedRecord, SecureNote
from .passwords import estimate_strength, generate_password
from .serializers import (
    CredentialSerializer,
    PasswordCheckRequestSerializer,
    PasswordCheckResponseSerializer,
    PasswordGenerateRequestSerializer,
    PasswordGenerateResponseSerializer,
    RevealResponseSerializer,
    SecureNoteSerializer,
    annotate_reuse,
)

_ORDERINGS = {"title", "updated_at", "created_at", "expiry_date"}


class NoStoreMixin:
    """Vault responses must never be cached by browsers or intermediaries."""

    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        response["Cache-Control"] = "no-store"
        response["Pragma"] = "no-cache"
        return response


class OwnerScopedMixin(OrganizationScopedMixin):
    """Object-level permission: you only ever see your own records.

    Deliberately NOT widened for administrators. Holding an admin role never grants access to
    another person's credentials. Access for non-owners comes only from explicit grants and is resolved
    per object in `CredentialViewSet.get_object` (see apps.sharing.access).
    """

    def get_queryset(self):
        return super().get_queryset().filter(owner=self.request.user)


class _VaultViewSet(
    NoStoreMixin, OwnerScopedMixin, CreateModelMixin, ListModelMixin, RetrieveModelMixin, UpdateModelMixin, GenericViewSet
):
    """No DELETE route. Records are archived, never hard-deleted. The only way to read a secret is the
    `reveal` action, which runs the full security pipeline (apps.vault.pipeline)."""

    # subclasses: queryset, serializer_class, snapshot()
    throttle_scope = None  # DRF only lets @action override attributes the class defines; `reveal` sets its own

    def get_permissions(self):
        perms = [HasAppPermission("vault.use")()]
        if self.action in ("create", "update", "partial_update"):
            perms.append(NotLockedDown())  # writing secrets is blocked during an emergency lockdown
        return perms

    def snapshot(self, obj) -> dict:
        return {
            "title": obj.title,
            "category": obj.category,
            "tags": list(obj.tags),
            "status": obj.status,
        }

    def get_queryset(self):
        qs = super().get_queryset()
        p = self.request.query_params
        if self.action == "list":
            qs = qs.filter(status=p.get("status") or EncryptedRecord.Status.ACTIVE)
        if p.get("category"):
            qs = qs.filter(category=p["category"])
        if p.get("tag"):
            qs = qs.filter(tags__contains=[p["tag"].strip().lower()[:32]])
        ordering = p.get("ordering", "title")
        if ordering.lstrip("-") not in _ORDERINGS:
            ordering = "title"  # whitelist: never order by an arbitrary (e.g. encrypted) column
        return qs.order_by(ordering, "id")

    def _audit(self, obj, action_, reason, extra):
        record(
            action=action_,
            outcome=AuditEvent.Outcome.SUCCESS,
            actor=self.request.user,
            target_type=obj.AUDIT_TYPE,
            target_id=obj.pk,
            reason_code=reason,
            metadata={"title": obj.title, **extra},
            request=self.request,
        )

    def perform_create(self, serializer):
        obj = serializer.save()
        self._audit(obj, AuditEvent.Action.CREATE, "created", {"changes": changed_fields({}, self.snapshot(obj))})

    def perform_update(self, serializer):
        before = self.snapshot(serializer.instance)
        secret_before = bytes(getattr(serializer.instance, serializer.instance.SECRET_FIELD))
        obj = serializer.save()
        changes = changed_fields(before, self.snapshot(obj))
        extra = {}
        if bytes(getattr(obj, obj.SECRET_FIELD)) != secret_before:
            extra["rotated"] = True  # the fact of change only, never any value
        if changes or extra:
            self._audit(obj, AuditEvent.Action.EDIT, "updated", {"changes": changes, **extra})

    def _set_status(self, new_status, reason):
        obj = self.get_object()
        if obj.status != new_status:
            obj.status = new_status
            obj.save(update_fields=["status", "updated_at"])
            self._audit(obj, AuditEvent.Action.EDIT, reason, {"changes": {"status": {"from": None, "to": new_status}}})
        return Response(self.get_serializer(obj).data)

    @extend_schema(request=None, responses=RevealResponseSerializer)
    @action(detail=True, methods=["post"], throttle_classes=[ScopedRateThrottle], throttle_scope="reveal")
    @sensitive_variables()
    def reveal(self, request, pk=None):
        """Return the decrypted secret iff every pipeline step passes. POST (never GET): it has side
        effects (audit, and burning a view-once grant) and must not be prefetched or cached."""
        target = self.get_object()
        result = pipeline.reveal(request, target)
        field = "password" if isinstance(target, Credential) else "content"
        return Response(
            {field: result.secret, "via": result.via, "view_once": result.view_once, "grant_id": result.grant_id}
        )

    @extend_schema(request=None, responses=CredentialSerializer)
    @action(detail=True, methods=["post"])
    def archive(self, request, pk=None):
        return self._set_status(EncryptedRecord.Status.ARCHIVED, "archived")

    @extend_schema(request=None, responses=CredentialSerializer)
    @action(detail=True, methods=["post"])
    def unarchive(self, request, pk=None):
        return self._set_status(EncryptedRecord.Status.ACTIVE, "unarchived")


class CredentialViewSet(_VaultViewSet):
    queryset = Credential.objects.select_related("service", "owner")
    serializer_class = CredentialSerializer

    def get_object(self):
        """Owner OR holder of a usable grant. archive/unarchive stay owner-only (owner-scoped queryset)."""
        if self.action in ("archive", "unarchive"):
            return super().get_object()
        user, pk = self.request.user, str(self.kwargs["pk"])
        credential = None
        if pk.isdigit():
            credential = annotate_reuse(
                Credential.objects.select_related("service", "owner").filter(organization_id=user.organization_id)
            ).filter(pk=int(pk)).first()
        if credential is None:
            raise NoAccess()
        if self.action == "reveal":
            return credential  # the pipeline resolves access itself so every refusal is audited
        access = resolve_access(user, credential)  # 404 / 403 / 410 with a precise code
        if self.action in ("update", "partial_update") and not access.can_edit:
            raise EditNotGranted()
        credential._access = access
        return credential

    def snapshot(self, obj):
        data = super().snapshot(obj)
        data.update(
            service_id=obj.service_id,
            expiry_date=obj.expiry_date.isoformat() if obj.expiry_date else None,
            username=obj.username,
        )
        return data

    def get_queryset(self):
        qs = annotate_reuse(super().get_queryset())
        p = self.request.query_params
        if p.get("service"):
            qs = qs.filter(service_id=p["service"]) if p["service"].isdigit() else qs.none()
        if p.get("q"):
            q = p["q"][:100]
            qs = qs.filter(Q(title__icontains=q) | Q(username__icontains=q) | Q(service__name__icontains=q))
        today = timezone.now().date()
        if p.get("expiry") == "expired":
            qs = qs.filter(expiry_date__lt=today)
        elif p.get("expiry") == "soon":
            qs = qs.filter(expiry_date__gte=today, expiry_date__lte=today + timedelta(days=14))
        return qs

    def _audit(self, obj, action_, reason, extra):
        changes = extra.get("changes", {})
        if "username" in changes:  # record that it changed, not the value
            changes["username"] = {"changed": True}
        super()._audit(obj, action_, reason, extra)


class SecureNoteViewSet(_VaultViewSet):
    queryset = SecureNote.objects.select_related("owner")
    serializer_class = SecureNoteSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        if self.request.query_params.get("q"):
            qs = qs.filter(title__icontains=self.request.query_params["q"][:100])
        return qs


class _PasswordUtilityView(NoStoreMixin, APIView):
    permission_classes = [HasAppPermission("vault.use")]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "vault_secret"


class PasswordGenerateView(_PasswordUtilityView):
    @extend_schema(request=PasswordGenerateRequestSerializer, responses=PasswordGenerateResponseSerializer)
    def post(self, request):
        """Generate a password that satisfies the organization's active policy.

        The result is returned once and never stored, logged or audited. Requests that would produce a
        non-compliant password are rejected rather than silently adjusted.
        """
        ser = PasswordGenerateRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        opts = dict(ser.validated_data)
        policy = get_effective_policy(request.user.organization_id)
        length = opts.pop("length", max(20, policy.min_length))
        if length < policy.min_length:
            raise PolicyViolation("below_min_length", f"Your security policy requires at least {policy.min_length} characters.")
        if policy.require_symbols and not opts["symbols"]:
            raise PolicyViolation("symbols_required", "Your security policy requires symbols.")
        if not any(opts[k] for k in ("lowercase", "uppercase", "digits", "symbols")):
            return Response({"detail": "Select at least one character class."}, status=400)
        password = generate_password(length, **opts)
        s = estimate_strength(password)
        return Response(
            {
                "password": password,
                "strength": {"bits": s.bits, "label": s.label, "issues": list(s.issues)},
                "policy": {
                    "min_length": policy.min_length,
                    "require_symbols": policy.require_symbols,
                    "max_age_days": policy.max_age_days,
                },
            }
        )


class PasswordCheckView(_PasswordUtilityView):
    @extend_schema(request=PasswordCheckRequestSerializer, responses=PasswordCheckResponseSerializer)
    def post(self, request):
        """Strength/entropy estimate plus policy compliance. The password is never echoed or stored."""
        ser = PasswordCheckRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        password = ser.validated_data["password"]
        policy = get_effective_policy(request.user.organization_id)
        s = estimate_strength(password)
        problems = check_password_rules(password, policy)
        return Response(
            {
                "strength": {"bits": s.bits, "label": s.label, "issues": list(s.issues)},
                "policy_violations": problems,
                "compliant": not problems,
            }
        )
