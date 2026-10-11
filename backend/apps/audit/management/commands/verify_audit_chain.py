from django.core.management.base import BaseCommand, CommandError

from apps.audit.models import AuditEvent
from apps.audit.services import verify_chain


class Command(BaseCommand):
    help = "Recompute the audit hash chain for every organization and report tampering."

    def handle(self, *args, **options):
        org_ids = list(AuditEvent.objects.values_list("organization_id", flat=True).distinct())
        bad = 0
        for org_id in org_ids:
            ok, bad_id = verify_chain(org_id)
            label = f"organization={org_id}"
            if ok:
                self.stdout.write(self.style.SUCCESS(f"OK    {label}"))
            else:
                bad += 1
                self.stdout.write(self.style.ERROR(f"BROKEN {label} first bad event id={bad_id}"))
        if bad:
            raise CommandError(f"{bad} audit chain(s) failed verification.")
