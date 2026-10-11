from django.utils import timezone
from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers

from .models import REQUEST_MAX_HOURS, AccessRequest, Share


class PersonSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    email = serializers.EmailField()
    full_name = serializers.CharField()


def _person(u) -> dict:
    return {"id": u.pk, "email": u.email, "full_name": u.full_name}


class ShareSerializer(serializers.ModelSerializer):
    credential_title = serializers.CharField(source="credential.title", read_only=True)
    grantor = serializers.SerializerMethodField()
    grantee = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()

    class Meta:
        model = Share
        fields = [
            "id", "credential", "credential_title", "parent", "grantor", "grantee", "can_view", "can_edit",
            "can_share", "expires_at", "is_view_once", "status", "burned_at", "revoked_at", "revoked_via_cascade",
            "depth", "created_at",
        ]
        read_only_fields = fields

    @extend_schema_field(PersonSerializer)
    def get_grantor(self, obj) -> dict:
        return _person(obj.grantor)

    @extend_schema_field(PersonSerializer)
    def get_grantee(self, obj) -> dict:
        return _person(obj.grantee)

    def get_status(self, obj) -> str:
        return obj.status_at()


class ShareCreateSerializer(serializers.Serializer):
    grantee_email = serializers.EmailField(max_length=254)
    can_view = serializers.BooleanField(default=True)
    can_edit = serializers.BooleanField(default=False)
    can_share = serializers.BooleanField(default=False)
    is_view_once = serializers.BooleanField(default=False)
    expires_at = serializers.DateTimeField(required=False, allow_null=True)
    expires_in_hours = serializers.IntegerField(min_value=1, max_value=24 * 365, required=False)

    def validate(self, attrs):
        if attrs.get("expires_at") and attrs.get("expires_in_hours"):
            raise serializers.ValidationError("Give either expires_at or expires_in_hours, not both.")
        if attrs.get("expires_in_hours"):
            from datetime import timedelta

            attrs["expires_at"] = timezone.now() + timedelta(hours=attrs.pop("expires_in_hours"))
        attrs.pop("expires_in_hours", None)
        return attrs


class AccessRequestCreateSerializer(serializers.Serializer):
    credential_uid = serializers.UUIDField()
    reason = serializers.CharField(min_length=10, max_length=500)
    requested_hours = serializers.IntegerField(min_value=1, max_value=REQUEST_MAX_HOURS)
    want_edit = serializers.BooleanField(default=False)


class AccessDecisionSerializer(serializers.Serializer):
    note = serializers.CharField(max_length=300, required=False, allow_blank=True, default="")
    hours = serializers.IntegerField(min_value=1, max_value=REQUEST_MAX_HOURS, required=False)


class AccessRequestSerializer(serializers.ModelSerializer):
    credential_uid = serializers.UUIDField(source="credential.uid", read_only=True)
    credential_title = serializers.CharField(source="credential.title", read_only=True)
    requester = serializers.SerializerMethodField()
    decided_by = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    resulting_share = serializers.PrimaryKeyRelatedField(read_only=True)
    can_decide = serializers.SerializerMethodField()

    class Meta:
        model = AccessRequest
        fields = [
            "id", "credential_uid", "credential_title", "requester", "reason", "requested_hours", "want_edit",
            "status", "decided_by", "decided_at", "decision_note", "resulting_share", "can_decide", "created_at",
        ]
        read_only_fields = fields

    @extend_schema_field(PersonSerializer)
    def get_requester(self, obj) -> dict:
        return _person(obj.requester)

    @extend_schema_field(PersonSerializer(allow_null=True))
    def get_decided_by(self, obj) -> dict | None:
        return _person(obj.decided_by) if obj.decided_by_id else None

    def get_status(self, obj) -> str:
        return obj.effective_status()

    def get_can_decide(self, obj) -> bool:
        from .services import can_decide

        return obj.effective_status() == AccessRequest.Status.PENDING and can_decide(self.context["request"].user, obj)
