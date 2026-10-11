from getpass import getpass

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError

from apps.accounts.models import AccountStatus, User
from apps.accounts.rbac import assign_role, create_organization


class Command(BaseCommand):
    help = "Create the organization, seed its roles and create the first Platform Administrator."

    def add_arguments(self, parser):
        parser.add_argument("--name", required=True)
        parser.add_argument("--slug", required=True)
        parser.add_argument("--admin-email", required=True)
        parser.add_argument("--admin-name", required=True)

    def handle(self, *args, **o):
        password = getpass("Admin password (input hidden): ")
        if password != getpass("Repeat password: "):
            raise CommandError("Passwords do not match.")
        try:
            validate_password(password)
        except ValidationError as exc:
            raise CommandError("; ".join(exc.messages))

        org = create_organization(o["name"], o["slug"])
        admin = User.objects.create_user(
            o["admin_email"], password, organization=org, full_name=o["admin_name"], status=AccountStatus.ACTIVE
        )
        assign_role(admin, "PLATFORM_ADMIN")
        self.stdout.write(self.style.SUCCESS(f"Created organization '{org.name}' with admin {admin.email}."))
