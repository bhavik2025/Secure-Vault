from rest_framework import serializers

from .models import AuditEvent


class AuditEventSerializer(serializers.ModelSerializer):
    """Output only. Hashes and raw metadata are intentionally not exposed here."""

    class Meta:
        model = AuditEvent
        fields = [
            "id", "created_at", "actor_email", "action", "outcome", "target_type",
            "target_id", "reason_code", "ip_address", "request_id",
        ]
        read_only_fields = fields
