from django.conf import settings
from django.db import models


class AuditImmutableError(Exception):
    """Raised on any attempt to modify or delete an audit event through the ORM."""


class AuditQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise AuditImmutableError("Audit events are append-only.")

    def delete(self):
        raise AuditImmutableError("Audit events are append-only.")

    def bulk_update(self, objs, fields, batch_size=None):
        raise AuditImmutableError("Audit events are append-only.")


class AuditEvent(models.Model):
    class Action(models.TextChoices):
        LOGIN = "LOGIN"
        LOGOUT = "LOGOUT"
        REVEAL = "REVEAL"
        COPY = "COPY"
        CREATE = "CREATE"
        EDIT = "EDIT"
        DELETE = "DELETE"
        SHARE = "SHARE"
        REVOKE = "REVOKE"
        ACCESS_REQUEST = "ACCESS_REQUEST"
        ACCESS_DECISION = "ACCESS_DECISION"
        DEVICE_TRUST_CHANGE = "DEVICE_TRUST_CHANGE"
        LOCKDOWN = "LOCKDOWN"
        UNLOCK = "UNLOCK"
        IMPORT = "IMPORT"
        POLICY_CHANGE = "POLICY_CHANGE"
        ACCOUNT_STATUS_CHANGE = "ACCOUNT_STATUS_CHANGE"
        AUTHZ_DENIED = "AUTHZ_DENIED"

    class Outcome(models.TextChoices):
        SUCCESS = "SUCCESS"
        DENIED = "DENIED"
        FAILURE = "FAILURE"

    # PROTECT (never SET_NULL/CASCADE): deleting a user or org must not rewrite or erase history.
    # Accounts are deactivated, not deleted.
    organization = models.ForeignKey(
        "organizations.Organization", null=True, on_delete=models.PROTECT, related_name="audit_events"
    )
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.PROTECT, related_name="+")
    actor_email = models.CharField(max_length=254, blank=True)  # snapshot; also set for failed logins
    action = models.CharField(max_length=30, choices=Action.choices)
    outcome = models.CharField(max_length=10, choices=Outcome.choices)
    target_type = models.CharField(max_length=60, blank=True)
    target_id = models.CharField(max_length=64, blank=True)
    reason_code = models.CharField(max_length=60, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=300, blank=True)
    device_fingerprint = models.CharField(max_length=128, blank=True)  # filled once devices exist
    request_id = models.CharField(max_length=36, blank=True)
    metadata = models.JSONField(default=dict, blank=True)  # always passed through scrub()
    created_at = models.DateTimeField()

    # Tamper evidence: entry_hash = HMAC(key, prev_hash || canonical(entry)). One chain per organization.
    prev_hash = models.CharField(max_length=64)
    entry_hash = models.CharField(max_length=64)

    objects = AuditQuerySet.as_manager()

    class Meta:
        db_table = "audit_event"
        ordering = ["id"]
        indexes = [
            models.Index(fields=["organization", "id"]),
            models.Index(fields=["organization", "action", "created_at"]),
            models.Index(fields=["actor", "created_at"]),
        ]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise AuditImmutableError("Audit events are append-only.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise AuditImmutableError("Audit events are append-only.")
