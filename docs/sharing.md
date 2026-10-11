# Sharing, delegation, reveal and the security pipeline

Sharing is built **on** the vault's existing authorization (ownership, organization scoping, the audit log,
the lockdown gate and the security policy). It is not a parallel permission system.

## Concepts
| Term | Meaning here |
|---|---|
| **Owner** | The user a credential belongs to. Ownership is a property of the credential, never of a role. |
| **Grant (share)** | One row giving a user VIEW, EDIT and/or SHARE on one credential. |
| **Delegation tree** | A grantee with SHARE can pass access on. `parent` links a grant to the grant it came from. |
| **Access lease / TTL** | `expires_at`. Checked at use time on every request, never by a cleanup job. |
| **View-once** | A VIEW-only grant that is *burned* (`burned_at`) by the first successful reveal. |
| **Cascading revocation** | Revoking a grant revokes its whole subtree in one transaction. |
| **Atomicity** | Several writes succeed or fail together; here a row lock plus a transaction makes burn-after-read exactly-once. |

## Permissions are independent
VIEW (read the secret), EDIT (change metadata / rotate the password), SHARE (delegate). EDIT does not
imply VIEW, SHARE does not imply either. Archive / unarchive remain owner-only.

## Delegation rules (all enforced server-side, all tested)
1. A delegate can never grant a permission they do not hold (`exceeds_upstream_permissions`).
2. A delegated grant cannot outlive its parent (`exceeds_upstream_lifetime`); if no expiry is given it inherits
   the parent's. A parent without expiry allows any lifetime.
3. Maximum depth 5 (`max_delegation_depth`). No cycles: you cannot delegate to anyone already in your chain,
   including the owner (`delegation_cycle`).
4. View-once grants are VIEW-only, cannot be delegated onward, and require `allow_view_once` in the security policy.
5. Grantees must be ACTIVE users in the same organization. Unknown, suspended and other-tenant addresses
   all get the same `invalid_grantee` answer (no account oracle).
6. A grant is **usable** only if it *and every ancestor* are unrevoked, unconsumed and unexpired. This is
   re-checked on every access, so authorization never relies on the cascade flag alone.

## Concurrency
- Grant creation, delegation and revocation take a row lock on the credential, so a child can never be attached to a
  parent that is being revoked at the same moment, and two identical share requests create exactly one grant.
- Reveal takes a row lock on the grant it is charged to. Of N simultaneous reveals of one view-once grant exactly one succeeds
  and the rest receive `410`. Tested with 8 threads, repeated 3 times.

## The reveal pipeline (`apps/vault/pipeline.py`)
```
1 authenticate -> 2 account ACTIVE -> 3 role vault.use + ownership/grant with VIEW -> 4 grant lease
-> 5 device trust -> 6 anomaly -> 7 lockdown -> 8 execute (lock, re-verify, decrypt, burn) -> 9 audit -> 10 respond
```
- **Denials never burn.** The burn is the last write, in the same transaction as the decryption. A failed decryption
  rolls everything back and leaves the grant unspent.
- **Status codes:** `404 no_access` (strangers cannot probe), `403 grant_revoked | grant_expired | view_not_granted`,
  `410 grant_consumed`, `423 lockdown_active`, `403 device_trust_unavailable`, `409 record_archived`.
- **Reveal is `POST`** (`/api/vault/credentials/{id}/reveal/`, `/api/vault/notes/{id}/reveal/`): it has side effects
  and must never be cached or prefetched. Notes are owner-only. A reusable grant is used in preference to spending
  a one-time grant.
- **Audit:** every outcome is recorded (`REVEAL` SUCCESS / DENIED / FAILURE) with the grant id, never the secret.
- **Ordinary responses never carry the secret:** list, retrieve, update and all errors return masked metadata only.

### Lockdown
`LockdownState` is a database row read fresh on every sensitive request. **No WebSocket message is involved in
enforcement.** It blocks: reveal, creating/updating credentials and notes, creating shares, creating and approving
access requests. It deliberately does **not** block revocation or reading masked metadata: containment must stay
possible. (The trigger/resolve API, session termination and the real-time broadcast arrive with the emergency
response module; today a row is created directly.)

### Honest scope notes
- **Device trust:** there is no device module yet, so when the policy sets `require_device_trust` the gate **fails
  closed** (reveal is denied for everyone) rather than pretending a device is trusted.
- **Anomaly detection** is an extension point (step 6) that currently denies nothing.
- The audit action `COPY` is not emitted: copying is a client action and cannot be reliably attested server-side.

## Access requests
- A requester names a credential by its unguessable `uid` (UUID), not by its sequential id.
- 1-168 hours; VIEW is implied, EDIT can be requested, SHARE never can. A pending request goes stale after 7 days.
- **Who decides:** the credential owner, or a manager holding `requests.approve` in the **owner's department**.
  Nobody decides their own request. A manager's approval authorizes, but the resulting grant is **issued by the owner**.
  The approver can shorten the lease, never extend it.
- Approval is blocked during lockdown; every step is audited (`ACCESS_REQUEST`, `ACCESS_DECISION`, `SHARE`) and notifies
  the relevant people. An approved grant is an ordinary grant and can be revoked like any other.

## Limits and what comes later
- Notifications are in-app records; real-time push comes with the WebSocket module.
- Reuse detection stays within the owner's vault; delegates never see it.
- Grant rows keep their history (revoked / consumed / expired) for audit; there is no hard delete.
