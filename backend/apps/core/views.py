from django.conf import settings
from django.db import connection
from django.middleware.csrf import get_token
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response


def _check_db() -> bool:
    try:
        with connection.cursor() as cur:
            cur.execute("SELECT 1")
            return cur.fetchone() == (1,)
    except Exception:
        return False


def _check_redis() -> bool:
    try:
        import redis

        return bool(redis.Redis.from_url(settings.REDIS_URL, socket_connect_timeout=2).ping())
    except Exception:
        return False


@api_view(["GET"])
@permission_classes([AllowAny])
def health(request):
    """Liveness/dependency probe. Reports booleans only: never error text or config."""
    db_ok, redis_ok = _check_db(), _check_redis()
    ok = db_ok and redis_ok
    return Response({"status": "ok" if ok else "degraded", "database": db_ok, "redis": redis_ok}, status=200 if ok else 503)


@api_view(["GET"])
@permission_classes([AllowAny])
def csrf(request):
    """Sets the `csrftoken` cookie so the SPA can send X-CSRFToken on unsafe requests."""
    get_token(request)
    return Response({"detail": "CSRF cookie set"})
