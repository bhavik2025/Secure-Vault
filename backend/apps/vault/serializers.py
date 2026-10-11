import re
from datetime import timedelta

from django.db.models import Exists, OuterRef
from django.utils import timezone
from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers

from apps.catalog.models import ServiceCatalogEntry
from apps.core.validators import validate_safe_text
from apps.policies.enforcement import check_password_rules, default_expiry_date, get_effective_policy

from .models import Credential, EncryptedRecord, SecureNote
from .passwords import WEAK_BELOW_BITS, label_for_bits
from .services import seal_note_content, seal_password

MASK = "•" * 12  # bullet characters, fixed width: never hints at the real length
EXPIRING_SOON_DAYS = 14
MAX_NOTE_CHARS = 20_000
_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9 _.:-]{0,31}$")


def _policy(serializer):
    ctx = serializer.context
    if "_policy" not in ctx:
        ctx["_policy"] = get_effective_policy(ctx["request"].user.organization_id)
    return ctx["_policy"]


class TagsMixin:
    def validate_tags(self, value):
        seen, out = set(), []
        for raw in value:
            tag = str(raw).strip().lower()
            if not _TAG_RE.match(tag):
                raise serializers.ValidationError(
                    "Tags are 1-32 characters: letters, digits, space and . _ : - (starting with a letter or digit)."
                )
            if tag not in seen:
                seen.add(tag)
                out.append(tag)
        if len(out) > 10:
            raise serializers.ValidationError("At most 10 tags.")
        return out


class OwnerField(serializers.Serializer):
    id = serializers.IntegerField()
    email = serializers.EmailField()
    full_name = serializers.CharField()


class _BaseRecordSerializer(TagsMixin, serializers.ModelSerializer):
    title = serializers.CharField(min_length=2, max_length=150, validators=[validate_safe_text])
    tags = serializers.ListField(child=serializers.CharField(max_length=64), required=False, max_length=30)
    owner = serializers.SerializerMethodField()

    @extend_schema_field(OwnerField)
    def get_owner(self, obj) -> dict:
        return {"id": obj.owner_id, "email": obj.owner.email, "full_name": obj.owner.full_name}

    def validate(self, attrs):
        if self.instance is not None and self.instance.status == EncryptedRecord.Status.ARCHIVED:
            raise serializers.ValidationError("This item is archived. Unarchive it before editing.")
        return attrs


class CredentialSerializer(_BaseRecordSerializer):
    # Write-only: never serialized back, never logged, never audited.
    password = serializers.CharField(write_only=True, max_length=256, trim_whitespace=False, required=False)
    username = serializers.CharField(max_length=254, required=False, allow_blank=True, validators=[validate_safe_text])
    service = serializers.PrimaryKeyRelatedField(
        queryset=ServiceCatalogEntry.objects.all(), required=False, allow_null=True
    )
    expiry_date = serializers.DateField(required=False, allow_null=True)

    password_masked = serializers.SerializerMethodField()
    has_password = serializers.SerializerMethodField()
    service_name = serializers.SerializerMethodField()
    strength = serializers.SerializerMethodField()
    expiry_state = serializers.SerializerMethodField()
    reused_in_my_vault = serializers.SerializerMethodField()
    warnings = serializers.SerializerMethodField()

    class Meta:
        model = Credential
        fields = [
            "id", "title", "service", "service_name", "username", "password", "password_masked", "has_password",
            "category", "tags", "expiry_date", "expiry_state", "status", "owner", "strength",
            "reused_in_my_vault", "warnings", "password_changed_at", "created_at", "updated_at",
        ]
        # status changes only via archive/unarchive. Encrypted columns are not fields at all.
        read_only_fields = ["id", "status", "password_changed_at", "created_at", "updated_at"]

    # -- output (metadata only; nothing here can contain the secret) --
    def get_password_masked(self, obj) -> str:
        return MASK

    def get_has_password(self, obj) -> bool:
        return True

    def get_service_name(self, obj) -> str | None:
        return obj.service.name if obj.service_id else None

    def get_strength(self, obj) -> dict:
        return {"bits": round(obj.entropy_bits, 1), "label": label_for_bits(obj.entropy_bits)}

    def _today(self):
        return timezone.now().date()

    def get_expiry_state(self, obj) -> str:
        if obj.expiry_date is None:
            return "none"
        today = self._today()
        if obj.expiry_date < today:
            return "expired"
        if obj.expiry_date <= today + timedelta(days=EXPIRING_SOON_DAYS):
            return "expiring_soon"
        return "ok"

    def get_reused_in_my_vault(self, obj) -> bool:
        # Scope is deliberately the owner's OWN vault. An org-wide "is this reused?" answer would be a
        # password-guessing oracle: create a credential with a guess and see whether anyone else has it.
        annotated = getattr(obj, "reused", None)
        if annotated is not None:
            return bool(annotated)
        return Credential.objects.filter(
            owner_id=obj.owner_id, blind_index=obj.blind_index, status=Credential.Status.ACTIVE
        ).exclude(pk=obj.pk).exists()

    def get_warnings(self, obj) -> list[str]:
        warnings = []
        state = self.get_expiry_state(obj)
        if state in ("expired", "expiring_soon"):
            warnings.append(state)
        if obj.entropy_bits < WEAK_BELOW_BITS:
            warnings.append("weak_password")
        if self.get_reused_in_my_vault(obj):
            warnings.append("reused_in_my_vault")
        max_age = _policy(self).max_age_days
        if max_age and obj.password_changed_at + timedelta(days=max_age) < timezone.now():
            warnings.append("older_than_policy_max_age")
        return warnings

    # -- input validation --
    def validate_service(self, service):
        if service is None:
            return None
        org_id = self.context["request"].user.organization_id
        if service.organization_id != org_id:
            raise serializers.ValidationError('Invalid pk "%s" - object does not exist.' % service.pk)
        unchanged = self.instance is not None and self.instance.service_id == service.pk
        if service.status != ServiceCatalogEntry.Status.ACTIVE and not unchanged:
            raise serializers.ValidationError("This service is inactive.")
        return service

    def validate(self, attrs):
        attrs = super().validate(attrs)
        policy = _policy(self)
        creating = self.instance is None

        if creating and "password" not in attrs:
            raise serializers.ValidationError({"password": "This field is required."})
        if "password" in attrs:
            problems = check_password_rules(attrs["password"], policy)
            if problems:
                raise serializers.ValidationError({"password": problems})

        today = self._today()
        if "expiry_date" in attrs:
            expiry = attrs["expiry_date"]
            if expiry is None:
                if policy.max_age_days is not None:
                    raise serializers.ValidationError({"expiry_date": "Your security policy requires an expiry date."})
            else:
                if expiry <= today:
                    raise serializers.ValidationError({"expiry_date": "Expiry must be in the future."})
                if policy.max_age_days is not None and expiry > today + timedelta(days=policy.max_age_days):
                    raise serializers.ValidationError(
                        {"expiry_date": f"Your security policy allows at most {policy.max_age_days} days."}
                    )
        elif creating or "password" in attrs:
            # Not specified: a new or freshly rotated password gets the policy's default lifetime.
            attrs["expiry_date"] = default_expiry_date(policy, today)

        if creating and not attrs.get("category") and attrs.get("service"):
            attrs["category"] = attrs["service"].category
        return attrs

    def create(self, validated):
        password = validated.pop("password")
        request_user = self.context["request"].user
        credential = Credential(organization=request_user.organization, owner=request_user, **validated)
        seal_password(credential, password)
        credential.save()
        return credential

    def update(self, instance, validated):
        password = validated.pop("password", None)
        for field, value in validated.items():
            setattr(instance, field, value)
        if password is not None:
            seal_password(instance, password)
        instance.save()
        return instance


class SecureNoteSerializer(_BaseRecordSerializer):
    content = serializers.CharField(
        write_only=True, max_length=MAX_NOTE_CHARS, trim_whitespace=False, required=False, allow_blank=False
    )
    content_masked = serializers.SerializerMethodField()
    has_content = serializers.SerializerMethodField()

    class Meta:
        model = SecureNote
        fields = [
            "id", "title", "content", "content_masked", "has_content", "category", "tags", "status", "owner",
            "created_at", "updated_at",
        ]
        read_only_fields = ["id", "status", "created_at", "updated_at"]

    def get_content_masked(self, obj) -> str:
        return MASK

    def get_has_content(self, obj) -> bool:
        return True

    def validate(self, attrs):
        attrs = super().validate(attrs)
        if self.instance is None and "content" not in attrs:
            raise serializers.ValidationError({"content": "This field is required."})
        return attrs

    def create(self, validated):
        content = validated.pop("content")
        user = self.context["request"].user
        note = SecureNote(organization=user.organization, owner=user, **validated)
        seal_note_content(note, content)
        note.save()
        return note

    def update(self, instance, validated):
        content = validated.pop("content", None)
        for field, value in validated.items():
            setattr(instance, field, value)
        if content is not None:
            seal_note_content(instance, content)
        instance.save()
        return instance


def annotate_reuse(queryset):
    """Annotate each credential with whether the same owner holds another ACTIVE one with an equal password."""
    return queryset.annotate(
        reused=Exists(
            Credential.objects.filter(
                owner_id=OuterRef("owner_id"), blind_index=OuterRef("blind_index"), status=Credential.Status.ACTIVE
            ).exclude(pk=OuterRef("pk"))
        )
    )


# --- password utilities ----------------------------------------------------------------------

class PasswordGenerateRequestSerializer(serializers.Serializer):
    length = serializers.IntegerField(min_value=8, max_value=128, required=False)
    lowercase = serializers.BooleanField(default=True)
    uppercase = serializers.BooleanField(default=True)
    digits = serializers.BooleanField(default=True)
    symbols = serializers.BooleanField(default=True)
    exclude_ambiguous = serializers.BooleanField(default=False)


class StrengthSerializer(serializers.Serializer):
    bits = serializers.FloatField()
    label = serializers.CharField()
    issues = serializers.ListField(child=serializers.CharField())


class PolicySummarySerializer(serializers.Serializer):
    min_length = serializers.IntegerField()
    require_symbols = serializers.BooleanField()
    max_age_days = serializers.IntegerField(allow_null=True)


class PasswordGenerateResponseSerializer(serializers.Serializer):
    password = serializers.CharField()
    strength = StrengthSerializer()
    policy = PolicySummarySerializer()


class PasswordCheckRequestSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=256, trim_whitespace=False, write_only=True)


class PasswordCheckResponseSerializer(serializers.Serializer):
    strength = StrengthSerializer()
    policy_violations = serializers.ListField(child=serializers.CharField())
    compliant = serializers.BooleanField()
