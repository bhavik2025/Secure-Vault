"""Permission catalogue and default role definitions (the code is the source of truth).

Design rules enforced by tests:
  * No permission exists that reads other people's secrets. Revealing a credential will be
    decided by ownership or an explicit, unexpired grant, never by role. So even a Platform
    Administrator cannot reveal arbitrary credentials.
  * `vault.use` means "may manage credentials I own". It carries no cross-user reach.
  * Roles are per-organization rows, but permissions are a global catalogue.
"""
from django.db import transaction

from apps.organizations.models import Organization

from .models import AppPermission, Role

PERMISSIONS: dict[str, str] = {
    "org.view": "View organization details",
    "org.manage": "Edit organization settings",
    "departments.view": "View departments",
    "departments.manage": "Create and edit departments",
    "users.view": "View employees",
    "users.manage": "Manage employee accounts and account status",
    "roles.manage": "Assign and manage roles",
    "audit.view": "View the audit trail",
    "policies.manage": "Manage security policies",
    "services.manage": "Manage the service catalogue",
    "imports.manage": "Run and review employee imports",
    "devices.review": "Review and approve device trust",
    "alerts.view": "View security alerts",
    "incidents.manage": "Manage security incidents",
    "lockdown.trigger": "Trigger emergency lockdown",
    "lockdown.resolve": "Resolve emergency lockdown",
    "requests.approve": "Approve or reject access requests in scope",
    "reports.view": "View reports in scope",
    "vault.use": "Create and manage credentials the user owns",
}

ROLE_DEFINITIONS: dict[str, dict] = {
    "PLATFORM_ADMIN": {
        "name": "Platform Administrator",
        "permissions": [
            "org.view", "org.manage", "departments.view", "departments.manage", "users.view", "users.manage",
            "roles.manage", "audit.view", "policies.manage", "services.manage", "imports.manage",
            "devices.review", "alerts.view", "lockdown.trigger", "lockdown.resolve", "reports.view", "vault.use",
        ],
    },
    "SECURITY_ADMIN": {
        # lockdown.trigger is NOT a default: it must be granted explicitly.
        "name": "Security Administrator",
        "permissions": [
            "org.view", "departments.view", "users.view", "audit.view", "devices.review",
            "alerts.view", "incidents.manage", "reports.view", "vault.use",
        ],
    },
    "DEPARTMENT_MANAGER": {
        "name": "Department Manager",
        "permissions": ["org.view", "departments.view", "users.view", "requests.approve", "reports.view", "vault.use"],
    },
    "EMPLOYEE": {
        "name": "Employee",
        "permissions": ["org.view", "vault.use"],
    },
}


def sync_permissions() -> None:
    for codename, description in PERMISSIONS.items():
        AppPermission.objects.update_or_create(codename=codename, defaults={"description": description})


@transaction.atomic
def seed_roles(organization: Organization) -> None:
    """Idempotently create the system roles for an organization."""
    sync_permissions()
    perms = {p.codename: p for p in AppPermission.objects.all()}
    for code, definition in ROLE_DEFINITIONS.items():
        role, _ = Role.objects.get_or_create(
            organization=organization, code=code, defaults={"name": definition["name"], "is_system": True}
        )
        role.permissions.set([perms[c] for c in definition["permissions"]])


@transaction.atomic
def create_organization(name: str, slug: str) -> Organization:
    organization = Organization.objects.create(name=name, slug=slug)
    seed_roles(organization)
    return organization


def assign_role(user, role_code: str) -> None:
    """Attach one of the user's *own organization's* roles. Cross-tenant assignment is impossible."""
    role = Role.objects.get(organization_id=user.organization_id, code=role_code)
    user.roles.add(role)
    user.__dict__.pop("_app_perm_cache", None)
