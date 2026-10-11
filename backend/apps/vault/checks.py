from django.core.checks import Error, Warning, register

from .crypto import CryptoConfigError, load_keyring


@register()
def vault_key_configuration(app_configs, **kwargs):
    """`manage.py check` (and every server start) validates the key configuration.

    Not configured -> Warning (a fresh checkout can still run unrelated commands; the vault itself
    fails closed). Configured but invalid -> Error.
    """
    from django.conf import settings

    if not settings.VAULT_KEY_ENCRYPTION_KEYS_B64 and not settings.VAULT_BLIND_INDEX_KEY_B64:
        return [
            Warning(
                "Vault keys are not configured; the vault will refuse to encrypt or decrypt.",
                hint="Run `manage.py generate_vault_keys` and put the output in .env.",
                id="vault.W001",
            )
        ]
    try:
        load_keyring()
    except CryptoConfigError as exc:
        return [Error(f"Invalid vault key configuration: {exc}", id="vault.E001")]
    return []
