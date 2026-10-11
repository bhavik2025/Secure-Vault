from rest_framework import serializers

from .models import Department, Organization


class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = ["id", "name", "slug", "is_active", "created_at"]
        read_only_fields = fields


class DepartmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Department
        fields = ["id", "name", "code", "head", "status", "created_at"]
        read_only_fields = ["id", "created_at"]  # `organization` is never accepted from the client

    def validate_head(self, head):
        org_id = self.context["request"].user.organization_id
        if head is not None and head.organization_id != org_id:
            raise serializers.ValidationError("Invalid department head.")  # same text as unknown id: no oracle
        return head

    def validate(self, attrs):
        org_id = self.context["request"].user.organization_id
        qs = Department.objects.filter(organization_id=org_id)
        if self.instance:
            qs = qs.exclude(pk=self.instance.pk)
        for field in ("code", "name"):
            if field in attrs and qs.filter(**{field: attrs[field]}).exists():
                raise serializers.ValidationError({field: f"A department with this {field} already exists."})
        return attrs
