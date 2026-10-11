import base64

from .base import *  # noqa: F401,F403

# Tests use real PostgreSQL (row locks / advisory locks / triggers need it) but no Redis
# dependency for unit-level tests. Redis-backed behaviour is covered by the health test.
CHANNEL_LAYERS = {"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}}
CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]  # speed only; tests only
REST_FRAMEWORK = {
    **REST_FRAMEWORK,  # noqa: F405
    "DEFAULT_THROTTLE_CLASSES": [],
    # Generous rates so unrelated tests never trip them; dedicated tests lower them.
    "DEFAULT_THROTTLE_RATES": {
        "anon": "1000/min", "user": "1000/min", "login": "1000/min", "vault_secret": "1000/min",
    },
}
AUDIT_HMAC_KEY = "test-only-audit-hmac-key-not-a-secret"


def _b64(seed: bytes) -> str:
    return base64.b64encode((seed * 32)[:32]).decode()


# Deterministic, obviously-fake test keys (never reuse outside tests). Two KEK versions let the
# rotation tests run; the blind-index key is deliberately different from both.
VAULT_KEY_ENCRYPTION_KEYS_B64 = {1: _b64(b"test-kek-one-"), 2: _b64(b"test-kek-two-")}
VAULT_ACTIVE_KEK_VERSION = 1
VAULT_BLIND_INDEX_KEY_B64 = _b64(b"test-blind-index-")
