import base64
import os

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = (
        "Print freshly generated vault keys (32 random bytes each, base64) for your .env. "
        "Run once at setup; with --kek-version N print just a new KEK for rotation."
    )

    def add_arguments(self, parser):
        parser.add_argument("--kek-version", type=int, default=None, help="Only emit VAULT_KEK_V<N> (rotation).")

    def handle(self, *args, **options):
        def key() -> str:
            return base64.b64encode(os.urandom(32)).decode()

        v = options["kek_version"]
        self.stderr.write("These are SECRETS. Put them in .env (git-ignored) or your secret manager. Never commit them.")
        if v:
            self.stdout.write(f"VAULT_KEK_V{v}={key()}")
            self.stderr.write(f"Then set VAULT_KEK_ACTIVE_VERSION={v} and run `manage.py rewrap_vault_keys`.")
        else:
            self.stdout.write(f"VAULT_KEK_V1={key()}")
            self.stdout.write("VAULT_KEK_ACTIVE_VERSION=1")
            self.stdout.write(f"VAULT_BLIND_INDEX_KEY={key()}")
