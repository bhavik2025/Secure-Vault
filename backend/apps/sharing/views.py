from django.db.models import Q
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.generics import GenericAPIView, ListAPIView
from rest_framework.mixins import ListModelMixin, RetrieveModelMixin
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from apps.accounts.permissions import HasAppPermission
from apps.core.api_errors import NoAccess
from apps.lockdown.permissions import NotLockedDown
from apps.vault.models import Credential
from apps.vault.views import NoStoreMixin

from . import services
from .access import resolve_access, shared_with
from .models import AccessRequest, Share
from .serializers import (
    AccessDecisionSerializer,
    AccessRequestCreateSerializer,
    AccessRequestSerializer,
    ShareCreateSerializer,
    ShareSerializer,
)

_USE_VAULT = HasAppPermission("vault.use")


class _Base(NoStoreMixin):
    permission_classes = [_USE_VAULT]


def _credential_or_404(user, credential_id) -> Credential:
    credential = Credential.objects.filter(pk=credential_id, organization_id=user.organization_id).first()
    if credential is None:
        raise NoAccess()
    return credential


class CredentialShareView(_Base, ListModelMixin, GenericAPIView):
    """GET: grants on this credential (the owner sees all, a delegate sees the ones they issued).
    POST: share it (owner) or delegate it (holder of a SHARE grant)."""

    serializer_class = ShareSerializer

    def get_permissions(self):
        perms = [_USE_VAULT()]
        if self.request.method == "POST":
            perms.append(NotLockedDown())  # creating access is blocked during lockdown; revoking never is
        return perms

    def get_queryset(self):
        credential = _credential_or_404(self.request.user, self.kwargs["credential_id"])
        access = resolve_access(self.request.user, credential)
        qs = Share.objects.filter(credential=credential).select_related("credential", "grantor", "grantee")
        return qs if access.role == "owner" else qs.filter(grantor=self.request.user)

    @extend_schema(responses=ShareSerializer(many=True))
    def get(self, request, credential_id):
        return self.list(request)

    @extend_schema(request=ShareCreateSerializer, responses={201: ShareSerializer})
    def post(self, request, credential_id):
        ser = ShareCreateSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        share = services.create_share(request=request, actor=request.user, credential_id=credential_id, grantee_email=ser.validated_data.pop("grantee_email"), **ser.validated_data)
        share = Share.objects.select_related("credential", "grantor", "grantee").get(pk=share.pk)
        return Response(ShareSerializer(share).data, status=status.HTTP_201_CREATED)


class CredentialShareTreeView(_Base, GenericAPIView):
    """The full delegation tree. Owner only."""

    serializer_class = ShareSerializer

    @extend_schema(responses={200: dict})
    def get(self, request, credential_id):
        credential = _credential_or_404(request.user, credential_id)
        if credential.owner_id != request.user.pk:
            raise NoAccess()
        return Response({"credential": credential.pk, "tree": services.build_tree(credential)})


class ShareRevokeView(_Base, GenericAPIView):
    serializer_class = ShareSerializer

    @extend_schema(request=None, responses=ShareSerializer)
    def post(self, request, pk):
        share, count = services.revoke_share(request=request, actor=request.user, share_id=pk)
        share = Share.objects.select_related("credential", "grantor", "grantee").get(pk=share.pk)
        data = ShareSerializer(share).data
        data["grants_revoked"] = count
        return Response(data)


class SharedWithMeView(_Base, ListAPIView):
    serializer_class = ShareSerializer

    def get_queryset(self):
        return shared_with(self.request.user)


class SharedByMeView(_Base, ListAPIView):
    serializer_class = ShareSerializer

    def get_queryset(self):
        return (
            Share.objects.filter(grantor=self.request.user)
            .select_related("credential", "grantor", "grantee")
            .order_by("-id")
        )


class AccessRequestViewSet(_Base, ListModelMixin, RetrieveModelMixin, GenericViewSet):
    serializer_class = AccessRequestSerializer
    queryset = AccessRequest.objects.all()

    def get_permissions(self):
        perms = [_USE_VAULT()]
        if self.action in ("create", "approve"):
            perms.append(NotLockedDown())
        return perms

    def _reviewable(self, user):
        q = Q(credential__owner=user)
        if user.has_app_perm("requests.approve") and user.department_id:
            q |= Q(credential__owner__department_id=user.department_id)
        return Q(organization_id=user.organization_id) & q & ~Q(requester=user)

    def get_queryset(self):
        user = self.request.user
        base = AccessRequest.objects.select_related("credential", "credential__owner", "requester", "decided_by")
        mine = Q(requester=user)
        scope = self.request.query_params.get("scope", "mine")
        if scope == "review":
            qs = base.filter(self._reviewable(user))
        elif self.action == "retrieve":
            qs = base.filter(mine | self._reviewable(user))  # either side may open it
        else:
            qs = base.filter(mine)
        status_ = self.request.query_params.get("status")
        return qs.filter(status=status_) if status_ else qs

    @extend_schema(request=AccessRequestCreateSerializer, responses={201: AccessRequestSerializer})
    def create(self, request):
        ser = AccessRequestCreateSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data
        req = services.create_access_request(
            request=request, requester=request.user, credential_uid=d["credential_uid"], reason=d["reason"],
            hours=d["requested_hours"], want_edit=d["want_edit"],
        )
        req = AccessRequest.objects.select_related("credential", "credential__owner", "requester", "decided_by").get(pk=req.pk)
        return Response(AccessRequestSerializer(req, context={"request": request}).data, status=status.HTTP_201_CREATED)

    def _decide(self, request, pk, approve):
        ser = AccessDecisionSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        req = services.decide_access_request(
            request=request, actor=request.user, request_id=int(pk), approve=approve,
            note=ser.validated_data["note"], hours=ser.validated_data.get("hours"),
        )
        req = AccessRequest.objects.select_related("credential", "credential__owner", "requester", "decided_by").get(pk=req.pk)
        return Response(AccessRequestSerializer(req, context={"request": request}).data)

    @extend_schema(request=AccessDecisionSerializer, responses=AccessRequestSerializer)
    @action(detail=True, methods=["post"])
    def approve(self, request, pk=None):
        return self._decide(request, pk, True)

    @extend_schema(request=AccessDecisionSerializer, responses=AccessRequestSerializer)
    @action(detail=True, methods=["post"])
    def reject(self, request, pk=None):
        return self._decide(request, pk, False)

    @extend_schema(request=None, responses=AccessRequestSerializer)
    @action(detail=True, methods=["post"])
    def cancel(self, request, pk=None):
        req = services.cancel_access_request(request=request, actor=request.user, request_id=int(pk))
        req = AccessRequest.objects.select_related("credential", "credential__owner", "requester", "decided_by").get(pk=req.pk)
        return Response(AccessRequestSerializer(req, context={"request": request}).data)
