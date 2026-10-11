from django.apps import AppConfig


class VaultConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.vault"

    def ready(self):
        from . import checks  # noqa: F401  (registers the system check)
