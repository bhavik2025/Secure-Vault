from django.core.exceptions import ValidationError

from .enforcement import check_password_rules, get_effective_policy


class OrganizationPolicyPasswordValidator:
    """Django password validator driven by the user's organization policy.

    Used automatically by `validate_password()` (activation, reset, change-password, bootstrap).
    With no known user/organization it falls back to the built-in defaults.
    """

    def validate(self, password, user=None):
        org_id = getattr(user, "organization_id", None)
        problems = check_password_rules(password, get_effective_policy(org_id))
        if problems:
            raise ValidationError(problems, code="password_policy")

    def get_help_text(self):
        return "Your password must satisfy your organization's security policy."
