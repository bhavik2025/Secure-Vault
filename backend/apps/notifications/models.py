from django.conf import settings
from django.db import models


class Notification(models.Model):
    """In-app notification. Content is metadata only: never a secret, a key or a password."""

    class Type(models.TextChoices):
        SHARE_RECEIVED = "SHARE_RECEIVED"
        SHARE_REVOKED = "SHARE_REVOKED"
        ACCESS_REQUESTED = "ACCESS_REQUESTED"
        ACCESS_APPROVED = "ACCESS_APPROVED"
        ACCESS_REJECTED = "ACCESS_REJECTED"

    class Priority(models.TextChoices):
        LOW = "LOW"
        NORMAL = "NORMAL"
        HIGH = "HIGH"

    organization = models.ForeignKey("organizations.Organization", on_delete=models.PROTECT, related_name="+")
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="notifications")
    type = models.CharField(max_length=20, choices=Type.choices)
    title = models.CharField(max_length=150)
    message = models.CharField(max_length=500)
    priority = models.CharField(max_length=10, choices=Priority.choices, default=Priority.NORMAL)
    is_read = models.BooleanField(default=False)
    related_type = models.CharField(max_length=40, blank=True)
    related_id = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-id"]
        indexes = [models.Index(fields=["recipient", "is_read"], name="notif_recipient_read")]
