from django.conf import settings
from django.db import models


class LockdownState(models.Model):
    """Emergency freeze register.

    This step ships the model and the server-side GATE that consults it. The trigger/resolve API,
    session termination and WebSocket broadcast arrive with the emergency-response module. The gate
    reads the database on every sensitive request, so enforcement never depends on a client receiving
    any push notification.
    """

    class Scope(models.TextChoices):
        GLOBAL = "GLOBAL", "Whole organization"
        USER = "USER", "Targeted user"

    organization = models.ForeignKey("organizations.Organization", on_delete=models.PROTECT, related_name="lockdowns")
    scope = models.CharField(max_length=10, choices=Scope.choices)
    target_user = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    initiator = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="+")
    reason = models.CharField(max_length=300)
    is_active = models.BooleanField(default=True)
    terminated_session_count = models.PositiveIntegerField(default=0)
    triggered_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )

    class Meta:
        indexes = [models.Index(fields=["organization", "is_active"], name="lockdown_org_active")]
        constraints = [
            models.CheckConstraint(
                condition=(models.Q(scope="GLOBAL", target_user__isnull=True) | models.Q(scope="USER", target_user__isnull=False)),
                name="lockdown_scope_target_consistent",
            )
        ]

    def __str__(self):
        return f"{self.scope} lockdown ({'active' if self.is_active else 'resolved'})"
