from rest_framework import serializers

from apps.core.validators import validate_safe_text

from .models import MAX_AGE_CEIL, MAX_AGE_FLOOR, MIN_LENGTH_CEIL, MIN_LENGTH_FLOOR, SecurityPolicy


class SecurityPolicySerializer(serializers.ModelSerializer):
    name = serializers.CharField(min_length=2, max_length=100, validators=[validate_safe_text])
    min_length = serializers.IntegerField(min_value=MIN_LENGTH_FLOOR, max_value=MIN_LENGTH_CEIL, required=False)
    max_age_days = serializers.IntegerField(
        min_value=MAX_AGE_FLOOR, max_value=MAX_AGE_CEIL, required=False, allow_null=True
    )

    class Meta:
        model = SecurityPolicy
        fields = [
            "id", "name", "min_length", "require_symbols", "max_age_days",
            "allow_view_once", "require_device_trust", "is_active", "created_at", "updated_at",
        ]
        # `is_active` changes only via the activate action so the one-active invariant has one code path.
        read_only_fields = ["id", "is_active", "created_at", "updated_at"]

    def validate_name(self, value):
        value = value.strip()
        qs = SecurityPolicy.objects.filter(organization_id=self.context["request"].user.organization_id, name__iexact=value)
        if self.instance:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise serializers.ValidationError("A policy with this name already exists.")
        return value


class EffectivePolicySerializer(serializers.Serializer):
    """What is in force right now (the active policy, or built-in defaults)."""

    name = serializers.CharField()
    min_length = serializers.IntegerField()
    require_symbols = serializers.BooleanField()
    max_age_days = serializers.IntegerField(allow_null=True)
    allow_view_once = serializers.BooleanField()
    require_device_trust = serializers.BooleanField()
    source = serializers.CharField()
