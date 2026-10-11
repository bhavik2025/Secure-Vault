from django.contrib.auth import login as django_login
from django.contrib.auth import logout as django_logout
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework.viewsets import ReadOnlyModelViewSet

from apps.audit.models import AuditEvent
from apps.audit.services import record
from apps.core.scoping import OrganizationScopedMixin

from .models import User, UserSession
from .permissions import HasAppPermission
from .serializers import EmployeeSerializer, LoginSerializer, MeSerializer, StatusChangeSerializer
from .services import StatusChangeError, change_account_status, track_session

_BACKEND = "django.contrib.auth.backends.ModelBackend"
_INVALID = {"detail": "Invalid email or password."}  # identical for every failure cause


def _loggable_email(raw: str) -> str:
    """Users sometimes paste a password into the email box. Keep only email-shaped input."""
    return raw if "@" in raw and len(raw) <= 254 else "[not-an-email]"


class LoginView(APIView):
    authentication_classes: list = []  # no session auth on the login call itself
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "login"

    @extend_schema(request=LoginSerializer, responses={200: MeSerializer, 401: OpenApiResponse(description="Invalid email or password.")})
    def post(self, request):
        # Login CSRF: DRF skips CSRF for unauthenticated calls, so enforce it explicitly.
        SessionAuthentication().enforce_csrf(request)

        ser = LoginSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        email, password = ser.validated_data["email"], ser.validated_data["password"]

        user = User.objects.select_related("organization").filter(email__iexact=email).first()
        if user is None:
            User().set_password(password)  # burn comparable time so timing doesn't reveal unknown emails
            reason = "unknown_user"
        elif not user.check_password(password):
            reason = "bad_password"
        elif not user.is_active:
            reason = f"account_{user.status.lower()}"
        else:
            reason = ""

        if reason:
            record(
                action=AuditEvent.Action.LOGIN,
                outcome=AuditEvent.Outcome.DENIED,
                actor=None,
                organization=user.organization if user else None,
                actor_email=_loggable_email(email),
                reason_code=reason,
                request=request,
            )
            return Response(_INVALID, status=status.HTTP_401_UNAUTHORIZED)

        django_login(request, user, backend=_BACKEND)  # rotates the session key (anti-fixation)
        track_session(request, user)
        record(action=AuditEvent.Action.LOGIN, outcome=AuditEvent.Outcome.SUCCESS, actor=user, request=request)
        return Response(MeSerializer(user).data)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(request=None, responses={204: None})
    def post(self, request):
        user = request.user
        UserSession.objects.filter(session_key=request.session.session_key).delete()
        record(action=AuditEvent.Action.LOGOUT, outcome=AuditEvent.Outcome.SUCCESS, actor=user, request=request)
        django_logout(request)  # flushes the server-side session
        return Response(status=status.HTTP_204_NO_CONTENT)


class MeView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(responses=MeSerializer)
    def get(self, request):
        return Response(MeSerializer(request.user).data)


class EmployeeViewSet(OrganizationScopedMixin, ReadOnlyModelViewSet):
    queryset = User.objects.prefetch_related("roles").order_by("email")
    serializer_class = EmployeeSerializer

    def get_permissions(self):
        code = "users.manage" if self.action == "set_status" else "users.view"
        return [HasAppPermission(code)()]

    @extend_schema(request=StatusChangeSerializer, responses=EmployeeSerializer)
    @action(detail=True, methods=["post"], url_path="status")
    def set_status(self, request, pk=None):
        target = self.get_object()  # org-scoped queryset: other tenants' users are 404
        ser = StatusChangeSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        try:
            change_account_status(
                actor=request.user,
                target=target,
                new_status=ser.validated_data["status"],
                reason=ser.validated_data["reason"],
                request=request,
            )
        except StatusChangeError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(EmployeeSerializer(target).data)
