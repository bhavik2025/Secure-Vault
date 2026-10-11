from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.db.models.functions import Lower

# Single source of truth for sensible defaults and hard limits.
DEFAULTS = {
    "min_length": 12,
    "require_symbols": True,
    "max_age_days": 90,
    "allow_view_once": True,
    "require_device_trust": False,
}
MIN_LENGTH_FLOOR, MIN_LENGTH_CEIL = 8, 128
MAX_AGE_FLOOR, MAX_AGE_CEIL = 1, 730


class SecurityPolicy(models.Model):
    """An organization's credential and device rules. Many may exist; exactly one is active."""

    organization = models.ForeignKey("organizations.Organization", on_delete=models.PROTECT, related_name="policies")
    name = models.CharField(max_length=100)
    min_length = models.PositiveSmallIntegerField(
        default=DEFAULTS["min_length"], validators=[MinValueValidator(MIN_LENGTH_FLOOR), MaxValueValidator(MIN_LENGTH_CEIL)]
    )
    require_symbols = models.BooleanField(default=DEFAULTS["require_symbols"])
    # null = passwords never expire. Otherwise the default credential lifetime and hygiene threshold.
    max_age_days = models.PositiveSmallIntegerField(
        null=True, blank=True, default=DEFAULTS["max_age_days"],
        validators=[MinValueValidator(MAX_AGE_FLOOR), MaxValueValidator(MAX_AGE_CEIL)],
    )
    allow_view_once = models.BooleanField(default=DEFAULTS["allow_view_once"])
    require_device_trust = models.BooleanField(default=DEFAULTS["require_device_trust"])
    is_active = models.BooleanField(default=False)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    source = "organization"

    class Meta:
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(Lower("name"), "organization", name="uniq_policy_name_ci_per_org"),
            # The database itself guarantees at most one active policy per organization.
            models.UniqueConstraint(
                fields=["organization"], condition=models.Q(is_active=True), name="one_active_policy_per_org"
            ),
            models.CheckConstraint(
                condition=models.Q(min_length__gte=MIN_LENGTH_FLOOR, min_length__lte=MIN_LENGTH_CEIL),
                name="policy_min_length_range",
            ),
            models.CheckConstraint(
                condition=models.Q(max_age_days__isnull=True)
                | models.Q(max_age_days__gte=MAX_AGE_FLOOR, max_age_days__lte=MAX_AGE_CEIL),
                name="policy_max_age_range",
            ),
        ]

    def __str__(self):
        return f"{self.name} ({'active' if self.is_active else 'inactive'})"
