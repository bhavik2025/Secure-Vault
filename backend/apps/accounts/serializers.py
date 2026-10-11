from rest_framework import serializers

from .models import AccountStatus, User


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=254)
    password = serializers.CharField(max_length=256, trim_whitespace=False, write_only=True)


class MeSerializer(serializers.ModelSerializer):
    """Identity for the UI. `permissions` only drives what the UI shows; the server re-checks."""

    organization = serializers.SerializerMethodField()
    department = serializers.SerializerMethodField()
    roles = serializers.SerializerMethodField()
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["id", "email", "full_name", "organization", "department", "roles", "permissions"]
        read_only_fields = fields

    def get_organization(self, u):
        return {"id": u.organization_id, "name": u.organization.name}

    def get_department(self, u):
        return {"id": u.department_id, "name": u.department.name} if u.department_id else None

    def get_roles(self, u):
        return sorted(u.roles.filter(organization_id=u.organization_id).values_list("code", flat=True))

    def get_permissions(self, u):
        return u.app_permissions()


class EmployeeSerializer(serializers.ModelSerializer):
    roles = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["id", "email", "full_name", "department", "status", "roles", "last_login"]
        read_only_fields = fields

    def get_roles(self, u):
        return sorted(r.code for r in u.roles.all() if r.organization_id == u.organization_id)


class StatusChangeSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=AccountStatus.choices)
    reason = serializers.CharField(min_length=3, max_length=300)
