from django.contrib.auth.base_user import BaseUserManager


class UserManager(BaseUserManager):
    use_in_migrations = True

    def create_user(self, email, password=None, *, organization, full_name="", status="ACTIVE", **extra):
        if not email:
            raise ValueError("Users must have an email address.")
        user = self.model(
            email=self.normalize_email(email).lower(),
            full_name=full_name,
            organization=organization,
            status=status,
            **extra,
        )
        user.set_password(password)  # hashes; None -> unusable password (e.g. invited users)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra):
        """Operator account for the Django admin / bootstrap only.

        Single-organization MVP: attaches to the default organization (created if missing).
        Superuser status grants no application permissions; assign roles for those.
        """
        from apps.organizations.models import Organization

        organization = extra.pop("organization", None) or Organization.objects.get_or_create(
            slug="default", defaults={"name": "Default Organization"}
        )[0]
        extra.update(is_staff=True, is_superuser=True)
        return self.create_user(email, password, organization=organization, **extra)
