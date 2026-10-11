"""Grant creation, delegation, revocation and access requests.

Concurrency model: every operation that changes a credential's grant tree first takes a row lock on
that credential (`SELECT ... FOR UPDATE`). Creation and revocation for the same credential therefore
serialize: a child can never be attached to a parent that is being revoked in a concurrent transaction.
"""
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from apps.accounts.models import AccountStatus, User
from apps.audit.models import AuditEvent
from apps.audit.services import record
from rest_framework.exceptions import APIException, PermissionDenied

from apps.core.api_errors import Conflict, NoAccess, ShareNotGranted, ShareRuleViolation
from apps.notifications.models import Notification
from apps.notifications.services import notify
from apps.policies.enforcement import ensure_view_once_allowed, get_effective_policy
from apps.vault.models import Credential

from .access import chain, resolve_access, usable_grants
from .models import MAX_DELEGATION_DEPTH, REQUEST_MAX_HOURS, AccessRequest, Share

ALL_NOT_PERMITTED = "You may not delegate that."


def _lock_credential(credential_id: int, organization_id: int) -> Credential:
    try:
        return Credential.objects.select_for_update().get(pk=credential_id, organization_id=organization_id)
    except Credential.DoesNotExist:
        raise NoAccess() from None


def _find_grantee(actor: User, email: str) -> User:
    """Same error for unknown, inactive and other-organization addresses: no account oracle."""
    grantee = User.objects.filter(organization_id=actor.organization_id, email__iexact=email, status=AccountStatus.ACTIVE).first()
    if grantee is None or grantee.pk == actor.pk:
        raise ShareRuleViolation("invalid_grantee", "No such active user in your organization.")
    return grantee


def _persist_share(*, request, actor, credential, grantor, grantee, parent, perms, expires_at, view_once, depth) -> Share:
    now = timezone.now()
    can_view, can_edit, can_share = perms
    if expires_at is not None and expires_at <= now:
        raise ShareRuleViolation("expiry_in_past", "The expiry must be in the future.")
    if grantee.pk == credential.owner_id:
        raise ShareRuleViolation("grantee_is_owner", "The owner already has full access.")
    duplicate = [g for g in usable_grants(grantee, credential, now) if g.grantor_id == grantor.pk]
    if duplicate:
        raise Conflict("This user already has an active share from you. Revoke it first to change it.")

    share = Share.objects.create(
        organization_id=credential.organization_id,
        credential=credential,
        parent=parent,
        grantor=grantor,
        grantee=grantee,
        can_view=can_view,
        can_edit=can_edit,
        can_share=can_share,
        expires_at=expires_at,
        is_view_once=view_once,
        depth=depth,
    )
    record(
        action=AuditEvent.Action.SHARE,
        outcome=AuditEvent.Outcome.SUCCESS,
        actor=actor,
        target_type="credential",
        target_id=credential.pk,
        reason_code="delegated" if parent else "direct",
        metadata={
            "share_id": share.pk,
            "grantee_id": grantee.pk,
            "view": can_view,
            "edit": can_edit,
            "share": can_share,
            "view_once": view_once,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "depth": depth,
        },
        request=request,
    )
    notify(
        grantee,
        Notification.Type.SHARE_RECEIVED,
        "A credential was shared with you",
        f"{grantor.full_name or grantor.email} shared '{credential.title}' with you"
        + (" (one-time view)." if view_once else "."),
        related_type="credential",
        related_id=credential.pk,
    )
    return share


@transaction.atomic
def create_share(*, request, actor: User, credential_id: int, grantee_email: str, can_view=True, can_edit=False,
                 can_share=False, expires_at=None, is_view_once=False) -> Share:
    credential = _lock_credential(credential_id, actor.organization_id)
    now = timezone.now()
    access = resolve_access(actor, credential, now)  # 404/403/410 as appropriate
    if credential.status != Credential.Status.ACTIVE:
        raise Conflict("Archived credentials cannot be shared.")
    grantee = _find_grantee(actor, grantee_email)

    perms = (bool(can_view), bool(can_edit), bool(can_share))
    if not any(perms):
        raise ShareRuleViolation("no_permission", "Grant at least one of view, edit or share.")
    if is_view_once:
        if perms != (True, False, False):
            raise ShareRuleViolation("view_once_view_only", "A one-time share can only grant VIEW.")
        ensure_view_once_allowed(get_effective_policy(actor.organization_id))  # raises PolicyViolation

    if access.role == "owner":
        return _persist_share(
            request=request, actor=actor, credential=credential, grantor=actor, grantee=grantee, parent=None,
            perms=perms, expires_at=expires_at, view_once=is_view_once, depth=1,
        )

    # --- delegation: the actor holds grants, not ownership ---
    sharers = [g for g in access.grants if g.can_share]
    if not sharers:
        raise ShareNotGranted()
    first_error = None
    for parent in sorted(sharers, key=lambda g: (g.expires_at is not None, -(g.expires_at.timestamp() if g.expires_at else 0), g.pk)):
        try:
            _check_delegation(parent, grantee, credential, perms, expires_at, now)
        except ShareRuleViolation as exc:
            first_error = first_error or exc
            continue
        lifetime = expires_at if expires_at is not None else parent.expires_at
        return _persist_share(
            request=request, actor=actor, credential=credential, grantor=actor, grantee=grantee, parent=parent,
            perms=perms, expires_at=lifetime, view_once=is_view_once, depth=parent.depth + 1,
        )
    raise first_error


def _check_delegation(parent: Share, grantee: User, credential: Credential, perms, expires_at, now) -> None:
    """The delegation invariants. A delegate can never exceed what they were given."""
    can_view, can_edit, can_share = perms
    if (can_view and not parent.can_view) or (can_edit and not parent.can_edit) or (can_share and not parent.can_share):
        raise ShareRuleViolation(
            "exceeds_upstream_permissions", "You cannot grant permissions you do not hold."
        )
    if parent.expires_at is not None and expires_at is not None and expires_at > parent.expires_at:
        raise ShareRuleViolation("exceeds_upstream_lifetime", "A delegated share cannot outlive the share it came from.")
    if parent.depth + 1 > MAX_DELEGATION_DEPTH:
        raise ShareRuleViolation("max_delegation_depth", f"Delegation is limited to {MAX_DELEGATION_DEPTH} levels.")
    upstream_users = {u for g in chain(parent) for u in (g.grantor_id, g.grantee_id)}
    if grantee.pk in upstream_users:
        raise ShareRuleViolation("delegation_cycle", "That user is already part of this delegation chain.")


def descendants(share: Share) -> list[Share]:
    """Every grant below `share`, breadth-first. Caller holds the credential lock."""
    out, frontier = [], [share.pk]
    while frontier:
        level = list(Share.objects.filter(parent_id__in=frontier))
        out.extend(level)
        frontier = [s.pk for s in level]
    return out


@transaction.atomic
def revoke_share(*, request, actor: User, share_id: int) -> tuple[Share, int]:
    """Revoke a grant and, atomically, every descendant. Returns (share, number_of_grants_revoked).

    Allowed for the credential owner (any grant) and the grantor (grants they issued). Deliberately NOT
    blocked by lockdown: during an incident, removing access must always work.
    """
    try:
        credential_id = Share.objects.values_list("credential_id", flat=True).get(pk=share_id, organization_id=actor.organization_id)
    except Share.DoesNotExist:
        raise NoAccess() from None
    credential = _lock_credential(credential_id, actor.organization_id)
    share = Share.objects.select_for_update().get(pk=share_id)  # re-read under the lock

    is_owner, is_grantor = credential.owner_id == actor.pk, share.grantor_id == actor.pk
    if not (is_owner or is_grantor):
        if share.grantee_id == actor.pk:
            raise PermissionDenied("Only the person who granted access, or the owner, can revoke it.")
        raise NoAccess()

    now = timezone.now()
    revoked = 0
    to_revoke = [share] + descendants(share)
    for s in to_revoke:
        if s.revoked_at is None:
            Share.objects.filter(pk=s.pk).update(
                revoked_at=now, revoked_by=actor, revoked_via_cascade=(s.pk != share.pk)
            )
            revoked += 1
            if s.grantee_id != actor.pk:
                notify(
                    s.grantee,
                    Notification.Type.SHARE_REVOKED,
                    "Access to a credential was revoked",
                    f"Your access to '{credential.title}' was revoked.",
                    priority=Notification.Priority.HIGH,
                    related_type="credential",
                    related_id=credential.pk,
                )
    if revoked:
        record(
            action=AuditEvent.Action.REVOKE,
            outcome=AuditEvent.Outcome.SUCCESS,
            actor=actor,
            target_type="credential",
            target_id=credential.pk,
            reason_code="cascade" if len(to_revoke) > 1 else "direct",
            metadata={"share_id": share.pk, "grants_revoked": revoked},
            request=request,
        )
    share.refresh_from_db()
    return share, revoked


def build_tree(credential: Credential) -> list[dict]:
    """Nested delegation tree for the owner's view. Holds metadata only."""
    now = timezone.now()
    shares = list(Share.objects.filter(credential=credential).select_related("grantor", "grantee").order_by("id"))
    nodes = {
        s.pk: {
            "id": s.pk,
            "grantor": s.grantor.email,
            "grantee": s.grantee.email,
            "view": s.can_view,
            "edit": s.can_edit,
            "share": s.can_share,
            "view_once": s.is_view_once,
            "expires_at": s.expires_at.isoformat() if s.expires_at else None,
            "status": s.status_at(now),
            "children": [],
        }
        for s in shares
    }
    roots = []
    for s in shares:
        (nodes[s.parent_id]["children"] if s.parent_id else roots).append(nodes[s.pk])
    return roots


# --- access requests ----------------------------------------------------------------------------

def can_decide(user: User, request_obj: AccessRequest) -> bool:
    """The credential owner, or a manager (`requests.approve`) in the same department as the owner.
    Nobody decides their own request."""
    if user.pk == request_obj.requester_id or user.organization_id != request_obj.organization_id:
        return False
    owner = request_obj.credential.owner
    if user.pk == owner.pk:
        return True
    return bool(user.has_app_perm("requests.approve") and user.department_id and user.department_id == owner.department_id)


def approvers_of(credential: Credential, exclude_user_id: int) -> list[User]:
    owner = credential.owner
    people = {owner.pk: owner}
    if owner.department_id:
        for u in User.objects.filter(
            organization_id=owner.organization_id, department_id=owner.department_id, status=AccountStatus.ACTIVE
        ):
            if u.has_app_perm("requests.approve"):
                people[u.pk] = u
    return [u for pk, u in people.items() if pk != exclude_user_id]


@transaction.atomic
def create_access_request(*, request, requester: User, credential_uid, reason: str, hours: int, want_edit: bool) -> AccessRequest:
    credential = Credential.objects.select_related("owner").filter(
        uid=credential_uid, organization_id=requester.organization_id, status=Credential.Status.ACTIVE
    ).first()
    if credential is None:
        raise NoAccess()
    if credential.owner_id == requester.pk:
        raise ShareRuleViolation("own_credential", "You own this credential.")
    if not 1 <= hours <= REQUEST_MAX_HOURS:
        raise ShareRuleViolation("invalid_duration", f"Duration must be 1-{REQUEST_MAX_HOURS} hours.")

    now = timezone.now()
    try:
        access = resolve_access(requester, credential, now)
    except APIException:  # no usable grant: exactly the situation in which a request makes sense
        access = None
    if access and access.can_view and (access.can_edit or not want_edit):
        raise Conflict("You already have this access.")

    # a stale pending request must not block a fresh one (unique-pending constraint)
    stale = AccessRequest.objects.filter(
        credential=credential, requester=requester, status=AccessRequest.Status.PENDING,
        created_at__lte=now - timedelta(days=7),
    )
    stale.update(status=AccessRequest.Status.EXPIRED)
    if AccessRequest.objects.filter(credential=credential, requester=requester, status=AccessRequest.Status.PENDING).exists():
        raise Conflict("You already have a pending request for this credential.")

    req = AccessRequest.objects.create(
        organization_id=requester.organization_id, credential=credential, requester=requester,
        reason=reason, requested_hours=hours, want_edit=want_edit,
    )
    record(
        action=AuditEvent.Action.ACCESS_REQUEST, outcome=AuditEvent.Outcome.SUCCESS, actor=requester,
        target_type="credential", target_id=credential.pk, reason_code="requested",
        metadata={"request_id": req.pk, "hours": hours, "edit": want_edit}, request=request,
    )
    for approver in approvers_of(credential, requester.pk):
        notify(
            approver, Notification.Type.ACCESS_REQUESTED, "Access request awaiting your decision",
            f"{requester.full_name or requester.email} requested access to '{credential.title}' for {hours}h.",
            priority=Notification.Priority.HIGH, related_type="access_request", related_id=req.pk,
        )
    return req


@transaction.atomic
def decide_access_request(*, request, actor: User, request_id: int, approve: bool, note: str = "", hours: int | None = None) -> AccessRequest:
    try:
        req = AccessRequest.objects.select_for_update().select_related("credential", "credential__owner", "requester").get(
            pk=request_id, organization_id=actor.organization_id
        )
    except AccessRequest.DoesNotExist:
        raise NoAccess() from None
    if not can_decide(actor, req):
        raise NoAccess()  # not yours to see
    if req.effective_status() != AccessRequest.Status.PENDING:
        raise Conflict(f"This request is already {req.effective_status().lower()}.")

    now = timezone.now()
    req.status = AccessRequest.Status.APPROVED if approve else AccessRequest.Status.REJECTED
    req.decided_by, req.decided_at, req.decision_note = actor, now, note[:300]

    if approve:
        granted_hours = min(hours or req.requested_hours, req.requested_hours)  # approvers can shorten, never extend
        credential = _lock_credential(req.credential_id, actor.organization_id)
        if credential.status != Credential.Status.ACTIVE:
            raise Conflict("This credential is archived.")
        # The OWNER is the grantor: a manager's approval authorizes, but only an owner can hand out the secret.
        req.resulting_share = _persist_share(
            request=request, actor=actor, credential=credential, grantor=credential.owner, grantee=req.requester,
            parent=None, perms=(True, req.want_edit, False), expires_at=now + timedelta(hours=granted_hours),
            view_once=False, depth=1,
        )
    req.save()
    record(
        action=AuditEvent.Action.ACCESS_DECISION, outcome=AuditEvent.Outcome.SUCCESS, actor=actor,
        target_type="credential", target_id=req.credential_id,
        reason_code="approved" if approve else "rejected",
        metadata={"request_id": req.pk, "requester_id": req.requester_id, "decided_by_owner": actor.pk == req.credential.owner_id},
        request=request,
    )
    notify(
        req.requester,
        Notification.Type.ACCESS_APPROVED if approve else Notification.Type.ACCESS_REJECTED,
        "Access request approved" if approve else "Access request rejected",
        f"Your request for '{req.credential.title}' was {'approved' if approve else 'rejected'}.",
        priority=Notification.Priority.HIGH, related_type="access_request", related_id=req.pk,
    )
    return req


@transaction.atomic
def cancel_access_request(*, request, actor: User, request_id: int) -> AccessRequest:
    req = AccessRequest.objects.select_for_update().filter(
        pk=request_id, requester=actor, organization_id=actor.organization_id
    ).first()
    if req is None:
        raise NoAccess()
    if req.effective_status() != AccessRequest.Status.PENDING:
        raise Conflict(f"This request is already {req.effective_status().lower()}.")
    req.status = AccessRequest.Status.CANCELLED
    req.save(update_fields=["status"])
    record(
        action=AuditEvent.Action.ACCESS_DECISION, outcome=AuditEvent.Outcome.SUCCESS, actor=actor,
        target_type="credential", target_id=req.credential_id, reason_code="cancelled",
        metadata={"request_id": req.pk}, request=request,
    )
    return req
