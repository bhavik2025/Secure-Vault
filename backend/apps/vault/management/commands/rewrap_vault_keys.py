from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.vault.crypto import CryptoError, load_keyring, rewrap_dek
from apps.vault.models import Credential, SecureNote


class Command(BaseCommand):
    help = (
        "KEK rotation: re-wrap every data key that is not under the ACTIVE key-encryption key. "
        "Secrets themselves are never decrypted. Safe to re-run; each record is its own transaction."
    )

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true", help="Count records that need re-wrapping; change nothing.")

    def handle(self, *args, **options):
        try:
            active = load_keyring().active_version
        except CryptoError as exc:
            raise CommandError(str(exc))
        total = failed = 0
        for model in (Credential, SecureNote):
            stale = model.objects.exclude(kek_version=active).values_list("pk", flat=True)
            for pk in list(stale):
                total += 1
                if options["dry_run"]:
                    continue
                try:
                    with transaction.atomic():
                        rec = model.objects.select_for_update().get(pk=pk)
                        rec.apply_sealed(rewrap_dek(rec.sealed(), purpose=rec.PURPOSE, org_id=rec.organization_id, uid=rec.uid))
                        rec.save(update_fields=["wrapped_dek", "kek_version", "enc_format"])
                except CryptoError as exc:
                    failed += 1
                    self.stderr.write(f"FAILED {model.__name__} id={pk}: {exc}")
        verb = "would re-wrap" if options["dry_run"] else "re-wrapped"
        self.stdout.write(f"{verb} {total - failed} of {total} records under KEK v{active}.")
        if failed:
            raise CommandError(f"{failed} record(s) could not be re-wrapped; keep the old KEK configured.")
