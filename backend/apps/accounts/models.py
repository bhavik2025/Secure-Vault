from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.db import models
from django.db.models.functions import Lower
from django.utils import timezone

from .managers import UserManager


class AppPermission(models.Model):
    """A fine-grained capability such as `audit.view`. The catalogue lives in `rbac.py`."""

    codename = models.CharField(max_length=64, unique=True)
    description = models.CharField(max_length=200)

    def __str__(self):
        return self.codename


class Role(models.Model):
    """A named bundle of permissions, defined per organization (tenant-isolated)."""

    organization = models.ForeignKey("organizations.Organization", on_delete=models.CASCADE, related_name="roles")
    code = models.CharField(max_length=40)
    name = models.CharField(max_length=80)
    permissions = models.ManyToManyField(AppPermission, related_name="roles", blank=True)
    is_system = models.BooleanField(default=False)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["organization", "code"], name="uniq_role_code_per_org")]

    def __str__(self):
        return f"{self.organization_id}:{self.code}"


class AccountStatus(models.TextChoices):
    INVITED = "INVITED", "Invited (not yet activated)"
    ACTIVE = "ACTIVE", "Active"
    SUSPENDED = "SUSPENDED", "Suspended"
    DEACTIVATED = "DEACTIVATED", "Deactivated"


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(max_length=254, unique=True)  # stored lowercase; Lower() constraint backs it up
    full_name = models.CharField(max_length=150)
    organization = models.ForeignKey("organizations.Organization", on_delete=models.PROTECT, related_name="users")
    department = models.ForeignKey(
        "organizations.Department", null=True, blank=True, on_delete=models.SET_NULL, related_name="members"
    )
    roles = models.ManyToManyField(Role, blank=True, related_name="users")
    status = models.CharField(max_length=12, choices=AccountStatus.choices, default=AccountStatus.INVITED)
    # `is_staff` only gates the Django admin site (operators). It confers NO application rights.
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["full_name"]

    class Meta:
        constraints = [models.UniqueConstraint(Lower("email"), name="uniq_user_email_ci")]
        indexes = [models.Index(fields=["organization", "status"])]

    def __str__(self):
        return self.email

    def save(self, *args, **kwargs):
        self.email = self.email.strip().lower()
        super().save(*args, **kwargs)

    @property
    def is_active(self) -> bool:
        """Django consults this on every request (session loading) and on login.

        Deriving it from `status` means suspending/deactivating an account kills its existing
        sessions on their very next request, with no session sweep required.
        """
        return self.status == AccountStatus.ACTIVE

    def has_app_perm(self, codename: str) -> bool:
        """Application RBAC check. Deliberately ignores `is_superuser`/`is_staff`.

        Only ACTIVE users, and only roles belonging to the user's own organization, count.
        """
        if not self.is_active:
            return False
        return codename in self._load_app_perms()

    def app_permissions(self) -> list[str]:
        return sorted(self._load_app_perms()) if self.is_active else []

    def _load_app_perms(self) -> set[str]:
        # Cached per instance (i.e. per request); never across requests, so revocations apply at once.
        cached = getattr(self, "_app_perm_cache", None)
        if cached is None:
            cached = set(
                AppPermission.objects.filter(
                    roles__users=self, roles__organization_id=self.organization_id
                ).values_list("codename", flat=True)
            )
            self._app_perm_cache = cached
        return cached


class UserSession(models.Model):
    """Maps a Django session to its user so all of a user's sessions can be revoked at once."""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="tracked_sessions")
    session_key = models.CharField(max_length=40, unique=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=300, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
