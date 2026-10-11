import pytest
from channels.testing import WebsocketCommunicator
from django.conf import settings
from django.db import connection

from config.asgi import application


@pytest.mark.django_db
def test_database_is_postgresql():
    assert connection.vendor == "postgresql"


@pytest.mark.django_db
def test_health_endpoint_is_public_and_reports_dependencies(client):
    resp = client.get("/api/health/")
    body = resp.json()
    assert set(body) == {"status", "database", "redis"}  # no config/error leakage
    assert body["database"] is True


def test_redis_reachable():
    import redis

    assert redis.Redis.from_url(settings.REDIS_URL, socket_connect_timeout=2).ping() is True


@pytest.mark.django_db
def test_csrf_endpoint_sets_cookie(client):
    resp = client.get("/api/auth/csrf/")
    assert resp.status_code == 200
    assert "csrftoken" in resp.cookies


def test_drf_is_deny_by_default():
    drf = settings.REST_FRAMEWORK
    assert drf["DEFAULT_PERMISSION_CLASSES"] == ["rest_framework.permissions.IsAuthenticated"]
    assert drf["DEFAULT_AUTHENTICATION_CLASSES"] == ["rest_framework.authentication.SessionAuthentication"]


def test_cors_allows_only_configured_origins(client):
    ok = client.get("/api/health/", HTTP_ORIGIN="http://localhost:5173")
    bad = client.get("/api/health/", HTTP_ORIGIN="https://evil.example")
    assert ok.headers.get("Access-Control-Allow-Origin") == "http://localhost:5173"
    assert "Access-Control-Allow-Origin" not in bad.headers


async def test_websocket_ping_roundtrip():
    comm = WebsocketCommunicator(application, "/ws/ping/", headers=[(b"origin", b"http://localhost:5173")])
    connected, _ = await comm.connect()
    assert connected
    assert (await comm.receive_json_from()) == {"type": "pong", "status": "ok"}
    await comm.disconnect()


async def test_websocket_rejects_foreign_origin():
    comm = WebsocketCommunicator(application, "/ws/ping/", headers=[(b"origin", b"https://evil.example")])
    connected, _ = await comm.connect()
    assert connected is False
