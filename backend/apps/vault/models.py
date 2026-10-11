import uuid

from django.conf import settings
from django.db import models

from apps.catalog.models import ServiceCatalogEntry

from .crypto import FORMAT_V1, PURPOSE_CREDENTIAL_PASSWORD, PURPOSE_NOTE_CONTENT, SealedSecret


class EncryptedRecord(models.Model):
    """Shared shape of every record that carries an envelope-encrypted secret.

    The secret itself lives in a concrete subclass's blob column; `wrapped_dek`, `kek_version` and
    `enc_format` describe how to open it. Plaintext is never a column.
    """

    class Status(models.TextChoices):
        ACTIVE = "ACTIVE", "Active"
        ARCHIVED = "ARCHIVED", "Archived"

    organization = models.ForeignKey("organizations.Organization", on_delete=models.PROTECT, related_name="+")
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="+")
    # Bound into the AES-GCM associated data: generated in Python BEFORE the first save.
    uid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    title = models.CharField(max_length=150)
    category = models.CharField(max_length=20, choices=ServiceCatalogEntry.Category.choices, default="OTHER")
    tags = models.JSONField(default=list, blank=True)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.ACTIVE)

    wrapped_dek = models.BinaryField()
    kek_version = models.PositiveSmallIntegerField()
    enc_format = models.PositiveSmallIntegerField(default=FORMAT_V1)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    PURPOSE: str  # set by subclasses
    AUDIT_TYPE: str
    SECRET_FIELD: str  # name of the blob column

    class Meta:
        abstract = True
        constraints = [models.CheckConstraint(condition=models.Q(kek_version__gte=1), name="%(class)s_kek_version_pos")]
        indexes = [models.Index(fields=["organization", "owner", "status"], name="%(class)s_org_owner_status")]

    def sealed(self) -> SealedSecret:
        return SealedSecret(
            enc_format=self.enc_format,
            kek_version=self.kek_version,
            wrapped_dek=bytes(self.wrapped_dek),
            payload=bytes(getattr(self, self.SECRET_FIELD)),
        )

    def apply_sealed(self, sealed: SealedSecret) -> None:
        self.enc_format = sealed.enc_format
        self.kek_version = sealed.kek_version
        self.wrapped_dek = sealed.wrapped_dek
        setattr(self, self.SECRET_FIELD, sealed.payload)

    def __str__(self):
        return f"{self.AUDIT_TYPE}:{self.pk}"


class Credential(EncryptedRecord):
    PURPOSE = PURPOSE_CREDENTIAL_PASSWORD
    AUDIT_TYPE = "credential"
    SECRET_FIELD = "password_enc"

    service = models.ForeignKey(ServiceCatalogEntry, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    username = models.CharField(max_length=254, blank=True)  # plaintext by design: needed for search/display
    password_enc = models.BinaryField()
    # HMAC-SHA-256 blind index of the password (separate key). Used ONLY for same-owner reuse detection.
    blind_index = models.CharField(max_length=64, db_index=False)
    entropy_bits = models.FloatField()  # estimate computed when the password was set; used for hygiene
    password_changed_at = models.DateTimeField()
    expiry_date = models.DateField(null=True, blank=True)

    class Meta(EncryptedRecord.Meta):
        indexes = EncryptedRecord.Meta.indexes + [
            models.Index(fields=["organization", "owner", "blind_index"], name="credential_reuse_lookup"),
            models.Index(fields=["expiry_date"], name="credential_expiry"),
        ]


class SecureNote(EncryptedRecord):
    PURPOSE = PURPOSE_NOTE_CONTENT
    AUDIT_TYPE = "secure_note"
    SECRET_FIELD = "content_enc"

    content_enc = models.BinaryField()
