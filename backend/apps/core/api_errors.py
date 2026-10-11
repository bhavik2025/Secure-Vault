"""API errors shared by the security pipeline, sharing and lockdown.

Status-code policy (deliberate; the codes leak as little as possible):
  404 no_access            - no relationship to the record at all (strangers cannot probe for existence)
  403 grant_revoked / grant_expired / view_not_granted / edit_not_granted / share_not_granted
  410 grant_consumed       - a view-once grant that was already used
  423 lockdown_active      - emergency lockdown blocks the action
  403 device_trust_unavailable - policy requires device trust and it cannot be established
"""
from rest_framework import status
from rest_framework.exceptions import APIException, NotFound, PermissionDenied


class NoAccess(NotFound):
    default_detail = "Not found."
    default_code = "no_access"


class GrantRevoked(PermissionDenied):
    default_detail = "This access has been revoked."
    default_code = "grant_revoked"


class GrantExpired(PermissionDenied):
    default_detail = "This access has expired."
    default_code = "grant_expired"


class GrantConsumed(APIException):
    status_code = status.HTTP_410_GONE
    default_detail = "This one-time access has already been used."
    default_code = "grant_consumed"


class ViewNotGranted(PermissionDenied):
    default_detail = "You do not have permission to view this secret."
    default_code = "view_not_granted"


class EditNotGranted(PermissionDenied):
    default_detail = "You do not have permission to edit this credential."
    default_code = "edit_not_granted"


class ShareNotGranted(PermissionDenied):
    default_detail = "You do not have permission to share this credential."
    default_code = "share_not_granted"


class DeviceTrustUnavailable(PermissionDenied):
    default_detail = "Your organization requires a trusted device, and device trust cannot be verified."
    default_code = "device_trust_unavailable"


class LockdownActive(APIException):
    status_code = status.HTTP_423_LOCKED
    default_detail = "An emergency lockdown is active. This action is blocked."
    default_code = "lockdown_active"


class RecordArchived(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = "This item is archived."
    default_code = "record_archived"


class Conflict(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = "Conflict."
    default_code = "conflict"


class DecryptionFailed(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = "The secret could not be decrypted."
    default_code = "decryption_failed"


class ShareRuleViolation(APIException):
    """A delegation rule was broken (permissions/lifetime exceed upstream, depth, cycle, ...)."""

    status_code = status.HTTP_400_BAD_REQUEST
    default_code = "share_rule_violation"

    def __init__(self, code: str, detail: str):
        super().__init__(detail=detail, code=code)
