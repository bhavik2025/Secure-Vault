from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.db.models.functions import Lower


class ServiceCatalogEntry(models.Model):
    """A third-party SaaS tool or internal service that credentials can be attached to.

    Never hard-deleted: credentials will reference entries (FK PROTECT), so retiring a
    service means setting it INACTIVE, which hides it from pickers but keeps history intact.
    """

    class Category(models.TextChoices):
        DATABASE = "DATABASE", "Database"
        CLOUD = "CLOUD", "Cloud platform"
        SAAS = "SAAS", "SaaS application"
        SOURCE_CONTROL = "SOURCE_CONTROL", "Source control / CI"
        INFRASTRUCTURE = "INFRASTRUCTURE", "Infrastructure / server"
        MONITORING = "MONITORING", "Monitoring / logging"
        OTHER = "OTHER", "Other"

    class Status(models.TextChoices):
        ACTIVE = "ACTIVE", "Active"
        INACTIVE = "INACTIVE", "Inactive"

    organization = models.ForeignKey("organizations.Organization", on_delete=models.PROTECT, related_name="services")
    name = models.CharField(max_length=120)
    category = models.CharField(max_length=20, choices=Category.choices, default=Category.OTHER)
    base_url = models.CharField(max_length=500)  # validated/normalized in the serializer
    icon_url = models.CharField(max_length=500, blank=True)
    default_port = models.PositiveIntegerField(
        null=True, blank=True, validators=[MinValueValidator(1), MaxValueValidator(65535)]
    )
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.ACTIVE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(Lower("name"), "organization", name="uniq_service_name_ci_per_org"),
            models.CheckConstraint(
                condition=models.Q(default_port__isnull=True) | models.Q(default_port__gte=1, default_port__lte=65535),
                name="service_port_range",
            ),
        ]
        indexes = [models.Index(fields=["organization", "status"])]

    def __str__(self):
        return self.name
