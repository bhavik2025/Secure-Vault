from .base import *  # noqa: F401,F403

# Tests use real PostgreSQL (row locks / advisory locks / triggers need it) but no Redis
# dependency for unit-level tests. Redis-backed behaviour is covered by the health test.
CHANNEL_LAYERS = {"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}}
CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]  # speed only; tests only
REST_FRAMEWORK = {
    **REST_FRAMEWORK,  # noqa: F405
    "DEFAULT_THROTTLE_CLASSES": [],
    # Generous login rate so unrelated tests never trip it; the throttle test lowers it.
    "DEFAULT_THROTTLE_RATES": {"anon": "1000/min", "user": "1000/min", "login": "1000/min"},
}
AUDIT_HMAC_KEY = "test-only-audit-hmac-key-not-a-secret"
