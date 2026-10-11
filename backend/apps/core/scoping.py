class OrganizationScopedMixin:
    """Restricts a DRF view's queryset to the requester's organization.

    This is the tenant-isolation choke point: object lookups (`get_object`) run against the
    already-filtered queryset, so another organization's row is simply "not found" (404),
    which also avoids confirming that the ID exists (IDOR / enumeration).
    """

    def get_queryset(self):
        return super().get_queryset().filter(organization_id=self.request.user.organization_id)
