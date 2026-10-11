from django.core.management.base import BaseCommand

from apps.accounts.rbac import provision_defaults
from apps.organizations.models import Organization


class Command(BaseCommand):
    help = "Re-sync the permission catalogue, system roles and default policy for every organization."

    def handle(self, *args, **options):
        for org in Organization.objects.all():
            provision_defaults(org)
            self.stdout.write(f"synced organization '{org.name}'")
        self.stdout.write(self.style.SUCCESS("Done."))
