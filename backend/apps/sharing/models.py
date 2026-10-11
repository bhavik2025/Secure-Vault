from datetime import timedelta

from django.conf import settings
from django.db import models
from django.db.models import Q
from django.utils import timezone

MAX_DELEGATION_DEPTH = 5
REQUEST_MAX_HOURS = 168  # one week
REQUEST_TTL = timedelta(days=7)  # a pending request nobody decided on goes stale


class Share(models.Model):
    """One grant of access to a credential. Grants form a delegation tree via `parent`.

    A grant is *usable* only if it and EVERY ancestor are not revoked, not consumed and not expired.
    Revoking a grant marks its whole subtree revoked in the same transaction (cascading revocation).
    """

    organization = models.ForeignKey("organizations.Organization", on_delete=models.PROTECT, related_name="+")
    credential = models.ForeignKey("vault.Credential", on_delete=models.PROTECT, related_name="shares")
    parent = models.ForeignKey("self", null=True, blank=True, on_delete=models.PROTECT, related_name="children")
    grantor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="+")
    grantee = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="received_shares")

    can_view = models.BooleanField(default=True)
    can_edit = models.BooleanField(default=False)
    can_share = models.BooleanField(default=False)

    expires_at = models.DateTimeField(null=True, blank=True)  # access lease; None = until revoked
    is_view_once = models.BooleanField(default=False)
    burned_at = models.DateTimeField(null=True, blank=True)  # set atomically on the first successful reveal

    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    revoked_via_cascade = models.BooleanField(default=False)

    depth = models.PositiveSmallIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["id"]
        indexes = [
            models.Index(fields=["credential", "grantee"], name="share_cred_grantee"),
            models.Index(fields=["parent"], name="share_parent"),
            models.Index(fields=["grantor"], name="share_grantor"),
        ]
        constraints = [
            models.CheckConstraint(condition=Q(can_view=True) | Q(can_edit=True) | Q(can_share=True), name="share_has_permission"),
            models.CheckConstraint(
                condition=Q(is_view_once=False) | (Q(can_view=True, can_edit=False, can_share=False)),
                name="share_view_once_is_view_only",
            ),
            models.CheckConstraint(condition=~Q(grantor=models.F("grantee")), name="share_not_self"),
            models.CheckConstraint(condition=Q(depth__gte=1, depth__lte=MAX_DELEGATION_DEPTH), name="share_depth_range"),
            models.CheckConstraint(condition=Q(burned_at__isnull=True) | Q(is_view_once=True), name="share_burn_only_view_once"),
        ]

    @staticmethod
    def effective_q(now):
        """The grant itself is neither revoked, consumed nor expired (ancestors are checked separately)."""
        return Q(revoked_at__isnull=True, burned_at__isnull=True) & (Q(expires_at__isnull=True) | Q(expires_at__gt=now))

    def status_at(self, now=None) -> str:
        now = now or timezone.now()
        if self.revoked_at:
            return "REVOKED"
        if self.burned_at:
            return "CONSUMED"
        if self.expires_at and self.expires_at <= now:
            return "EXPIRED"
        return "ACTIVE"

    def __str__(self):
        return f"Share {self.pk} on credential {self.credential_id}"


class AccessRequest(models.Model):
    class Status(models.TextChoices):
        PENDING = "PENDING"
        APPROVED = "APPROVED"
        REJECTED = "REJECTED"
        CANCELLED = "CANCELLED"
        EXPIRED = "EXPIRED"

    organization = models.ForeignKey("organizations.Organization", on_delete=models.PROTECT, related_name="+")
    credential = models.ForeignKey("vault.Credential", on_delete=models.PROTECT, related_name="access_requests")
    requester = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="access_requests")
    reason = models.CharField(max_length=500)
    requested_hours = models.PositiveSmallIntegerField()
    want_edit = models.BooleanField(default=False)  # VIEW is always implied; SHARE can never be requested
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.PENDING)
    decided_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    decided_at = models.DateTimeField(null=True, blank=True)
    decision_note = models.CharField(max_length=300, blank=True)
    resulting_share = models.ForeignKey(Share, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-id"]
        constraints = [
            models.UniqueConstraint(
                fields=["credential", "requester"], condition=Q(status="PENDING"), name="one_pending_request_per_user_credential"
            ),
            models.CheckConstraint(
                condition=Q(requested_hours__gte=1, requested_hours__lte=REQUEST_MAX_HOURS), name="request_hours_range"
            ),
        ]
        indexes = [models.Index(fields=["organization", "status"], name="request_org_status")]

    def effective_status(self, now=None) -> str:
        now = now or timezone.now()
        if self.status == self.Status.PENDING and self.created_at + REQUEST_TTL <= now:
            return self.Status.EXPIRED
        return self.status
