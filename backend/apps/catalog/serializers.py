from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

from apps.core.validators import ICON_URL_SCHEMES, SERVICE_URL_SCHEMES, normalize_url, validate_safe_text

from .models import ServiceCatalogEntry

TRACKED_FIELDS = ("name", "category", "base_url", "icon_url", "default_port", "status")


def snapshot(entry: ServiceCatalogEntry) -> dict:
    return {f: getattr(entry, f) for f in TRACKED_FIELDS}


def _url_field(value, schemes):
    try:
        return normalize_url(value, schemes=schemes)
    except DjangoValidationError as exc:
        raise serializers.ValidationError(exc.messages)


class ServiceSerializer(serializers.ModelSerializer):
    name = serializers.CharField(min_length=2, max_length=120, validators=[validate_safe_text])
    default_port = serializers.IntegerField(min_value=1, max_value=65535, required=False, allow_null=True)
    icon_url = serializers.CharField(max_length=500, required=False, allow_blank=True)

    class Meta:
        model = ServiceCatalogEntry
        fields = ["id", "name", "category", "base_url", "icon_url", "default_port", "status", "created_at", "updated_at"]
        # `status` changes only through the activate/deactivate actions; `organization` is never client-supplied.
        read_only_fields = ["id", "status", "created_at", "updated_at"]

    def validate_name(self, value):
        value = value.strip()
        qs = ServiceCatalogEntry.objects.filter(
            organization_id=self.context["request"].user.organization_id, name__iexact=value
        )
        if self.instance:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise serializers.ValidationError("A service with this name already exists.")
        return value

    def validate_base_url(self, value):
        return _url_field(value, SERVICE_URL_SCHEMES)

    def validate_icon_url(self, value):
        return _url_field(value, ICON_URL_SCHEMES) if value.strip() else ""
