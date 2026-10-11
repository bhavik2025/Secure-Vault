"""DEVELOPMENT ONLY demo data: a separate "Demo Corp" organization with one user per role.

Safety rules:
  * Refuses to run unless DEBUG=True, so it cannot touch a real deployment.
  * Uses its own organization (slug "demo"); it never modifies any other organization.
  * All demo users share one password. Supply it via the SECUREVAULT_DEMO_PASSWORD environment variable
    (it is then never printed), or let the command generate one and print it ONCE.
  * Re-running is safe: nothing is duplicated, and the demo users' password is reset to the chosen one.
  * Credential passwords are random and never printed; reveal them in the app.
"""
import os
import secrets
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from apps.accounts.models import AccountStatus, User
from apps.accounts.rbac import assign_role, create_organization, provision_defaults
from apps.catalog.models import ServiceCatalogEntry
from apps.organizations.models import Department, Organization
from apps.policies.enforcement import default_expiry_date, get_effective_policy
from apps.vault.crypto import CryptoError, load_keyring
from apps.vault.models import Credential, SecureNote
from apps.vault.passwords import generate_password
from apps.vault.services import seal_note_content, seal_password

PASSWORD_ENV = "SECUREVAULT_DEMO_PASSWORD"
DEMO_SLUG = "demo"
USERS = [
    # email, full name, role, department code
    ("admin@demo.example", "Dana Admin", "PLATFORM_ADMIN", None),
    ("security@demo.example", "Sam Security", "SECURITY_ADMIN", None),
    ("manager@demo.example", "Morgan Manager", "DEPARTMENT_MANAGER", "ENG"),
    ("alice@demo.example", "Alice Engineer", "EMPLOYEE", "ENG"),
    ("bob@demo.example", "Bob Engineer", "EMPLOYEE", "ENG"),
]
SERVICES = [
    ("GitHub", "SOURCE_CONTROL", "https://github.com", None),
    ("Production PostgreSQL", "DATABASE", "postgresql://db.demo.internal", 5432),
    ("AWS Console", "CLOUD", "https://console.aws.amazon.com", None),
]


class Command(BaseCommand):
    help = "DEVELOPMENT ONLY: create the 'Demo Corp' organization with a user in every role and sample vault data."

    def handle(self, *args, **options):
        if not settings.DEBUG:
            raise CommandError("seed_demo only runs with DEBUG=True. It must never touch a real deployment.")

        password = os.environ.get(PASSWORD_ENV) or ""
        generated = not password
        if generated:
            password = secrets.token_urlsafe(12) + "-7!"  # >= 12 chars with symbols: satisfies the default policy
        try:
            validate_password(password)
        except ValidationError as exc:
            raise CommandError(f"{PASSWORD_ENV} is not acceptable: {' '.join(exc.messages)}") from None

        with transaction.atomic():
            org, users = self._seed_org_and_users(password)
            made_vault = self._seed_vault(org, users)

        self.stdout.write(self.style.SUCCESS(f"Demo organization '{org.name}' is ready."))
        for email, name, role, _ in USERS:
            self.stdout.write(f"  {role:<20} {email:<24} {name}")
        if generated:
            self.stdout.write(self.style.WARNING(f"Demo password for every user above (shown once): {password}"))
        else:
            self.stdout.write(f"Demo users use the password from ${PASSWORD_ENV}.")
        if not made_vault:
            self.stdout.write(self.style.WARNING("Vault keys are not configured, so no sample credentials were created."))

    def _seed_org_and_users(self, password):
        org = Organization.objects.filter(slug=DEMO_SLUG).first()
        if org is None:
            org = create_organization("Demo Corp", DEMO_SLUG)
        else:
            provision_defaults(org)
        dept, _ = Department.objects.get_or_create(organization=org, code="ENG", defaults={"name": "Engineering"})

        users = {}
        for email, full_name, role, dept_code in USERS:
            user = User.objects.filter(email__iexact=email).first()
            if user is not None and user.organization_id != org.pk:
                raise CommandError(f"{email} already belongs to another organization; refusing to touch it.")
            if user is None:
                user = User.objects.create_user(email, password, organization=org, full_name=full_name, status=AccountStatus.ACTIVE)
            else:
                user.set_password(password)
                user.status = AccountStatus.ACTIVE
            user.department = dept if dept_code else None
            user.save()
            assign_role(user, role)
            users[role if role != "EMPLOYEE" else email.split("@")[0]] = user

        if dept.head_id is None:
            dept.head = users["DEPARTMENT_MANAGER"]
            dept.save(update_fields=["head"])

        for name, category, url, port in SERVICES:
            ServiceCatalogEntry.objects.get_or_create(
                organization=org, name=name, defaults={"category": category, "base_url": url, "default_port": port}
            )
        return org, users

    def _seed_vault(self, org, users) -> bool:
        try:
            load_keyring()
        except CryptoError:
            return False
        services = {s.name: s for s in ServiceCatalogEntry.objects.filter(organization=org)}
        policy = get_effective_policy(org.pk)
        today = timezone.now().date()

        def credential(owner, title, service, username, expiry=None):
            if Credential.objects.filter(owner=owner, title=title).exists():
                return
            c = Credential(
                organization=org, owner=owner, title=title, service=services[service], username=username,
                category=services[service].category, tags=["demo"],
                expiry_date=expiry or default_expiry_date(policy, today),
            )
            seal_password(c, generate_password(20))
            c.save()

        alice, bob = users["alice"], users["bob"]
        credential(alice, "GitHub deploy bot", "GitHub", "deploy-bot")
        credential(alice, "Production database (read-only)", "Production PostgreSQL", "readonly_app")
        credential(alice, "AWS break-glass", "AWS Console", "breakglass", expiry=today + timedelta(days=5))
        credential(bob, "Monitoring dashboard", "AWS Console", "grafana-admin")

        if not SecureNote.objects.filter(owner=alice, title="Payment provider API key").exists():
            note = SecureNote(organization=org, owner=alice, title="Payment provider API key", category="SAAS", tags=["demo"])
            seal_note_content(note, f"PAYMENTS_API_KEY=sk_test_{secrets.token_hex(16)}\n# rotate quarterly")
            note.save()
        return True
