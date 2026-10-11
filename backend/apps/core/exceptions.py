from rest_framework.exceptions import APIException
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
    response = drf_exception_handler(exc, context)
    # Machine-readable error code next to the human message, e.g. {"detail": "...", "code": "grant_consumed"}.
    if (
        response is not None
        and isinstance(exc, APIException)
        and isinstance(response.data, dict)
        and "detail" in response.data
        and "code" not in response.data
    ):
        response.data["code"] = getattr(response.data["detail"], "code", exc.default_code)
    return response
