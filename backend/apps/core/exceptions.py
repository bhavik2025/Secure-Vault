from rest_framework.response import Response
from rest_framework.views import exception_handler as drf_exception_handler


class PolicyViolation(Exception):
    """An action is forbidden by the organization's security policy (not by RBAC)."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def api_exception_handler(exc, context):
    if isinstance(exc, PolicyViolation):
        return Response({"detail": exc.message, "code": exc.code}, status=403)
    return drf_exception_handler(exc, context)
