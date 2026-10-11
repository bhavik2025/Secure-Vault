"""Base settings shared by every environment. All secrets come from the environment."""
import os
import re
from pathlib import Path

import environ

BASE_DIR = Path(__file__).resolve().parents[2]  # .../backend
REPO_ROOT = BASE_DIR.parent

env = environ.Env()
# Real environment variables win; .env at the repo root is a dev convenience.
environ.Env.read_env(REPO_ROOT / ".env", overwrite=False)

SECRET_KEY = env("DJANGO_SECRET_KEY")  # no default: fail loudly if missing
DEBUG = env.bool("DJANGO_DEBUG", default=False)
ALLOWED_HOSTS = env.list("DJANGO_ALLOWED_HOSTS", default=["localhost", "127.0.0.1"])

INSTALLED_APPS = [
    "daphne",  # must be first so `runserver` serves ASGI (WebSockets)
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "drf_spectacular",
    "corsheaders",
    "channels",
    "apps.core",
    "apps.organizations",
    "apps.accounts",
    "apps.audit",
    "apps.catalog",
    "apps.policies",
    "apps.vault",
    "apps.lockdown",
    "apps.notifications",
    "apps.sharing",
]

# Must be set before the first migration that touches user tables.
AUTH_USER_MODEL = "accounts.User"

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "apps.core.middleware.RequestIDMiddleware",
    "corsheaders.middleware.CorsMiddleware",  # before CommonMiddleware
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": env("POSTGRES_DB", default="securevault"),
        "USER": env("POSTGRES_USER", default="securevault"),
        "PASSWORD": env("POSTGRES_PASSWORD"),
        "HOST": env("POSTGRES_HOST", default="127.0.0.1"),
        "PORT": env("POSTGRES_PORT", default="5433"),
        "CONN_MAX_AGE": 60,
    }
}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    # Length and symbol rules come from the organization's active SecurityPolicy (built-in
    # default: 12 chars + symbol when an org has none), replacing Django's fixed length check.
    {"NAME": "apps.policies.validators.OrganizationPolicyPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

# --- Redis: Channels layer + cache -------------------------------------------------
REDIS_URL = env("REDIS_URL", default="redis://127.0.0.1:6379/0")
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {"hosts": [REDIS_URL]},
    }
}
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": REDIS_URL,
    }
}

# --- Sessions / CSRF (session-cookie auth, no JWT) -----------------------------------
SESSION_ENGINE = "django.contrib.sessions.backends.db"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
# Sliding idle timeout: the expiry is pushed forward on every request, so 30 minutes of
# inactivity ends the session. An absolute lifetime cap arrives with the security policy work.
SESSION_COOKIE_AGE = 60 * 30
SESSION_SAVE_EVERY_REQUEST = True

# HMAC key for the audit hash chain. Separate from SECRET_KEY and the vault keys.
AUDIT_HMAC_KEY = env("AUDIT_HMAC_KEY", default="")

# --- Vault cryptography (see docs/crypto.md). Raw base64 values; decoded and validated lazily by
# apps.vault.crypto so a bad value fails closed at first use and in `manage.py check`.
# The setting names contain "KEY" so Django's debug-page cleanser masks them.
# One entry per KEK version, e.g. env VAULT_KEK_V1, VAULT_KEK_V2 -> {1: "...", 2: "..."}.
VAULT_KEY_ENCRYPTION_KEYS_B64 = {
    int(m.group(1)): value
    for name, value in os.environ.items()
    if value and (m := re.fullmatch(r"VAULT_KEK_V(\d+)", name))
}
VAULT_ACTIVE_KEK_VERSION = env.int("VAULT_KEK_ACTIVE_VERSION", default=1)
# A DIFFERENT secret from every KEK: it only keys the HMAC blind index.
VAULT_BLIND_INDEX_KEY_B64 = env("VAULT_BLIND_INDEX_KEY", default="")
# The SPA must read the CSRF cookie to echo it in X-CSRFToken, so this one is NOT HttpOnly.
CSRF_COOKIE_HTTPONLY = False
CSRF_COOKIE_SAMESITE = "Lax"

FRONTEND_ORIGINS = env.list("FRONTEND_ORIGINS", default=["http://localhost:5173"])
CORS_ALLOWED_ORIGINS = FRONTEND_ORIGINS  # explicit allow-list, never CORS_ALLOW_ALL_ORIGINS
CORS_ALLOW_CREDENTIALS = True  # needed for cookies on cross-origin dev requests
CSRF_TRUSTED_ORIGINS = FRONTEND_ORIGINS

# --- DRF -----------------------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["rest_framework.authentication.SessionAuthentication"],
    # Deny by default: every endpoint must opt in to being public.
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "EXCEPTION_HANDLER": "apps.core.exceptions.api_exception_handler",
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_THROTTLE_CLASSES": ["rest_framework.throttling.AnonRateThrottle", "rest_framework.throttling.UserRateThrottle"],
    "DEFAULT_THROTTLE_RATES": {"anon": "60/min", "user": "300/min", "login": "10/min", "vault_secret": "30/min", "reveal": "20/min"},
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 25,
}

SPECTACULAR_SETTINGS = {
    "TITLE": "SecureVault API",
    "DESCRIPTION": "Zero-trust credential & access governance platform (server-side envelope encryption; not zero-knowledge).",
    "VERSION": "0.1.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "ENUM_NAME_OVERRIDES": {
        "AccountStatusEnum": "apps.accounts.models.AccountStatus",
        # Departments and services share identical ACTIVE/INACTIVE choices, hence one name.
        "ActiveInactiveStatusEnum": "apps.organizations.models.Department.Status",
        "RecordStatusEnum": "apps.vault.models.EncryptedRecord.Status",
    },
}

# Never log request bodies or Authorization/cookie headers (secrets live there).
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": "INFO"},
}
