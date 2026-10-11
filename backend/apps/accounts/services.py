from django.contrib.sessions.models import Session
from django.db import transaction

from apps.audit.models import AuditEvent
from apps.audit.services import record

from .models import AccountStatus, User, UserSession

# Allowed account-status transitions. DEACTIVATED is terminal; INVITED -> ACTIVE only happens
# through invitation activation (a later module), never by an admin toggle.
ALLOWED_TRANSITIONS = {
    AccountStatus.ACTIVE: {AccountStatus.SUSPENDED, AccountStatus.DEACTIVATED},
    AccountStatus.SUSPENDED: {AccountStatus.ACTIVE, AccountStatus.DEACTIVATED},
    AccountStatus.INVITED: {AccountStatus.DEACTIVATED},
    AccountStatus.DEACTIVATED: set(),
}


class StatusChangeError(Exception):
    pass


def track_session(request, user: User) -> None:
    UserSession.objects.update_or_create(
        session_key=request.session.session_key,
        defaults={
            "user": user,
            "ip_address": request.META.get("REMOTE_ADDR"),
            "user_agent": request.META.get("HTTP_USER_AGENT", "")[:300],
        },
    )


def revoke_user_sessions(user: User) -> int:
    """Delete every tracked server-side session for the user. Returns the number revoked."""
    keys = list(UserSession.objects.filter(user=user).values_list("session_key", flat=True))
    Session.objects.filter(session_key__in=keys).delete()
    UserSession.objects.filter(user=user).delete()
    return len(keys)


@transaction.atomic
def change_account_status(*, actor: User, target: User, new_status: str, reason: str, request=None) -> User:
    if actor.pk == target.pk:
        raise StatusChangeError("You cannot change your own account status.")
    if actor.organization_id != target.organization_id:
        raise StatusChangeError("Target is outside your organization.")  # views 404 first; defence in depth
    old = target.status
    if new_status not in ALLOWED_TRANSITIONS.get(old, set()):
        raise StatusChangeError(f"Cannot change status from {old} to {new_status}.")

    target.status = new_status
    target.save(update_fields=["status"])
    revoked = 0
    if new_status in (AccountStatus.SUSPENDED, AccountStatus.DEACTIVATED):
        revoked = revoke_user_sessions(target)
    record(
        action=AuditEvent.Action.ACCOUNT_STATUS_CHANGE,
        outcome=AuditEvent.Outcome.SUCCESS,
        actor=actor,
        target_type="user",
        target_id=target.pk,
        reason_code="admin_action",
        metadata={"from": old, "to": new_status, "reason": reason, "sessions_revoked": revoked},
        request=request,
    )
    return target
