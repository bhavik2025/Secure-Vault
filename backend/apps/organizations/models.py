from django.conf import settings
from django.db import models


class Organization(models.Model):
    """The tenant boundary. Every tenant-owned row carries an `organization` FK."""

    name = models.CharField(max_length=200, unique=True)
    slug = models.SlugField(max_length=64, unique=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class Department(models.Model):
    class Status(models.TextChoices):
        ACTIVE = "ACTIVE", "Active"
        INACTIVE = "INACTIVE", "Inactive"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT, related_name="departments")
    name = models.CharField(max_length=120)
    code = models.CharField(max_length=20)
    # The head must belong to the same organization; enforced in the serializer/service layer
    # because a cross-table check is not expressible as a simple DB constraint.
    head = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="headed_departments"
    )
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.ACTIVE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["organization", "code"], name="uniq_department_code_per_org"),
            models.UniqueConstraint(fields=["organization", "name"], name="uniq_department_name_per_org"),
        ]
        ordering = ["name"]

    def __str__(self):
        return f"{self.code} - {self.name}"
