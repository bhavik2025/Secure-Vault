"""Who may do what with a credential? One resolver, used by every vault endpoint.

Ownership is a property of the credential. Everyone else needs at least one *usable* grant: the grant and
all its ancestors must be unrevoked, unconsumed and unexpired. Roles never widen this (an administrator
who is not the owner or a grantee has no access).
"""
from dataclasses import dataclass, field

from django.utils import timezone

from apps.core.api_errors import GrantConsumed, GrantExpired, GrantRevoked, NoAccess

from .models import MAX_DELEGATION_DEPTH, Share


@dataclass
class Access:
    role: str  # "owner" | "grant"
    grants: list = field(default_factory=list)  # usable grants (empty for the owner)
    can_view: bool = False
    can_edit: bool = False
    can_share: bool = False
    expires_at: object = None

    def grant_for_reveal(self):
        """Which grant a reveal is charged to. Prefer a reusable grant so a one-time grant is only
        spent when it is the only way in."""
        viewers = [g for g in self.grants if g.can_view]
        reusable = [g for g in viewers if not g.is_view_once]
        return (reusable or viewers or [None])[0]


def chain(grant: Share) -> list[Share]:
    """The grant followed by its ancestors up to the owner-issued root (bounded by the depth limit)."""
    out, cur = [], grant
    while cur is not None and len(out) <= MAX_DELEGATION_DEPTH:
        out.append(cur)
        cur = cur.parent
    return out


def grant_usable(grant: Share, now=None) -> bool:
    now = now or timezone.now()
    return all(g.status_at(now) == "ACTIVE" for g in chain(grant))


def usable_grants(user, credential, now=None) -> list[Share]:
    now = now or timezone.now()
    candidates = (
        Share.objects.filter(credential=credential, grantee=user).filter(Share.effective_q(now)).select_related("parent")
    )
    return [g for g in candidates if grant_usable(g, now)]


def resolve_access(user, credential, now=None) -> Access:
    """Return the user's Access to the credential, or raise the precise API error.

    NoAccess (404) for people with no relationship at all; GrantRevoked/GrantExpired (403) or GrantConsumed
    (410) for people who did have a grant that is no longer usable.
    """
    now = now or timezone.now()
    if credential.organization_id != user.organization_id:
        raise NoAccess()
    if credential.owner_id == user.pk:
        return Access(role="owner", can_view=True, can_edit=True, can_share=True)

    grants = usable_grants(user, credential, now) if credential.status == "ACTIVE" else []
    if grants:
        return Access(
            role="grant",
            grants=grants,
            can_view=any(g.can_view for g in grants),
            can_edit=any(g.can_edit for g in grants),
            can_share=any(g.can_share for g in grants),
            expires_at=None if any(g.expires_at is None for g in grants) else max(g.expires_at for g in grants),
        )

    latest = Share.objects.filter(credential=credential, grantee=user).select_related("parent").order_by("-id").first()
    if latest is None or credential.status != "ACTIVE":
        raise NoAccess()
    state = latest.status_at(now)
    if state == "CONSUMED":
        raise GrantConsumed()
    if state == "EXPIRED":
        raise GrantExpired()
    raise GrantRevoked()  # revoked, or an ancestor was revoked/expired


def shared_with(user, now=None) -> list[Share]:
    """Usable grants the user currently holds (for the 'shared with me' list)."""
    now = now or timezone.now()
    qs = (
        Share.objects.filter(grantee=user, credential__status="ACTIVE", credential__organization_id=user.organization_id)
        .filter(Share.effective_q(now))
        .select_related("credential", "credential__owner", "credential__service", "grantor", "grantee", "parent")
        .order_by("-id")
    )
    return [g for g in qs if grant_usable(g, now)]
