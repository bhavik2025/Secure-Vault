# SecureVault API reference

Interactive docs: `http://127.0.0.1:8000/api/docs/` (Swagger UI) and `/api/schema/` (OpenAPI 3).
That generated schema is the source of truth; this page explains behaviour and rules.

**Conventions**
- Session-cookie authentication. Unsafe methods (POST/PUT/PATCH/DELETE) need the `X-CSRFToken` header
  (cookie `csrftoken`, set by `GET /api/auth/csrf/`).
- Lists are paginated: `{count, next, previous, results}` (25 per page, `?page=N`).
- Every endpoint is **organization-scoped**: another organization's object is `404`, never `403`.
- `403` = not authenticated, account not active, or the role lacks the permission (also audited as `AUTHZ_DENIED`).
- `400` = validation error, with a per-field message map.

## Authentication and identity
| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/api/health/` | public | `{status, database, redis}` |
| GET | `/api/auth/csrf/` | public | sets the CSRF cookie |
| POST | `/api/auth/login/` | public, CSRF, 10/min | `{email, password}`; every failure is the same `401` |
| POST | `/api/auth/logout/` | authenticated | `204`; destroys the server-side session |
| GET | `/api/auth/me/` | authenticated | identity, roles, permissions (UI hints only) |

## Organization
| Method | Path | Permission |
|---|---|---|
| GET | `/api/org/` | `org.view` |
| GET, POST | `/api/org/departments/` | `departments.view` / `departments.manage` |
| GET, PUT, PATCH | `/api/org/departments/{id}/` | same (no DELETE) |
| GET | `/api/org/employees/`, `/{id}/` | `users.view` |
| POST | `/api/org/employees/{id}/status/` | `users.manage`; `{status, reason}` |
| GET | `/api/audit/events/` | `audit.view`; filters `?action=&outcome=` |

## Service catalog (new)
A list of the third-party tools and internal systems credentials belong to.

| Method | Path | Permission | Behaviour |
|---|---|---|---|
| GET | `/api/org/services/` | `services.view` | Members without `services.manage` see **ACTIVE** entries only. Filters: `?q=` (name contains), `?category=`, `?status=` |
| POST | `/api/org/services/` | `services.manage` | Creates an ACTIVE entry; `201` |
| GET | `/api/org/services/{id}/` | `services.view` | Inactive entries are `404` for non-managers |
| PUT / PATCH | `/api/org/services/{id}/` | `services.manage` | `status` is read-only here |
| POST | `/api/org/services/{id}/deactivate/` | `services.manage` | Soft retire; idempotent |
| POST | `/api/org/services/{id}/activate/` | `services.manage` | Re-enable; idempotent |
| DELETE | any | - | `405`: entries are never hard-deleted |

Fields: `name` (2-120, no `<` `>` or control chars, unique per organization ignoring case), `category`
(`DATABASE, CLOUD, SAAS, SOURCE_CONTROL, INFRASTRUCTURE, MONITORING, OTHER`), `base_url`, `icon_url` (optional),
`default_port` (1-65535 or null), read-only `status`, `created_at`, `updated_at`.

URL rules:
- `base_url` schemes: `http, https, ssh, sftp, postgresql, mysql, mongodb, redis`. `icon_url`: `https` only.
- A host is required. Embedded credentials (`user:pass@host`), spaces, control characters, bad ports and
  anything over 500 characters are rejected. Scheme and host are lower-cased.
- The server never fetches these URLs (no SSRF surface); the browser loads the icon.

## Security policies (new)
An organization has many named policies and exactly **one active** (enforced by a database constraint).
New organizations start with an active "Default Policy".

| Method | Path | Permission | Behaviour |
|---|---|---|---|
| GET | `/api/org/security-policies/` | `policies.view` | Platform + Security Administrators |
| POST | `/api/org/security-policies/` | `policies.manage` | Created inactive (active only if the org has none) |
| GET | `/api/org/security-policies/{id}/` | `policies.view` | |
| PUT / PATCH | `/api/org/security-policies/{id}/` | `policies.manage` | Editing the active policy applies immediately; `is_active` is read-only |
| POST | `/api/org/security-policies/{id}/activate/` | `policies.manage` | Atomically swaps the active policy |
| GET | `/api/org/security-policies/active/` | `org.view` | What is in force now (any member). `source` is `organization` or `builtin_default` |
| DELETE | any | - | `405` |

| Field | Type / range | Default |
|---|---|---|
| `name` | 2-100 chars, unique per organization ignoring case | - |
| `min_length` | integer 8-128 | 12 |
| `require_symbols` | boolean | true |
| `max_age_days` | integer 1-730, or null = never expires | 90 |
| `allow_view_once` | boolean | true |
| `require_device_trust` | boolean | false |

### Where each rule is enforced (server-side)
| Rule | Enforcement point | Status |
|---|---|---|
| `min_length`, `require_symbols` | Django password validation (`OrganizationPolicyPasswordValidator`), used by account activation, reset and change-password | **Live** (unit-tested) |
| `min_length`, `require_symbols`, `max_age_days` for stored credentials | `check_password_rules`, `default_expiry_date` | Helpers ready; called by the vault phase |
| `allow_view_once` | `ensure_view_once_allowed` raises `PolicyViolation` (HTTP `403`, `code: view_once_disabled`) | Helper ready; called by the sharing phase |
| `require_device_trust` | `device_trust_required` | Helper ready; called by the device phase |

## Vault: credentials and secure notes (new)
All vault endpoints require `vault.use` **and** ownership: you only ever see your own records. Holding an
administrative role grants nothing here. Responses carry `Cache-Control: no-store`. **No endpoint returns a
secret**: there is deliberately no reveal route until the authorization/device/lockdown pipeline exists.

| Method | Path | Behaviour |
|---|---|---|
| GET | `/api/vault/credentials/` | Own ACTIVE credentials. `?status=ARCHIVED`, `?q=` (title/username/service), `?category=`, `?tag=`, `?service=<id>`, `?expiry=expired\|soon`, `?ordering=` (`title, updated_at, created_at, expiry_date`, optional `-`) |
| POST | `/api/vault/credentials/` | `{title, password, username?, service?, category?, tags?, expiry_date?}` -> `201` metadata only |
| GET / PATCH / PUT | `/api/vault/credentials/{id}/` | Another user's id is `404`. Sending `password` rotates it (new DEK + nonces). Archived items are read-only |
| POST | `/api/vault/credentials/{id}/archive/`, `/unarchive/` | Soft state change, idempotent, audited |
| GET, POST, GET/PATCH, archive | `/api/vault/notes/...` | Same shape with `content` (<= 20,000 chars) instead of `password`; no password policy applies |
| DELETE | any | `405` (records are archived, never hard-deleted) |

Credential response (no secret fields): `id, title, service, service_name, username, password_masked` (fixed 12
bullets, never the real length), `has_password, category, tags, expiry_date, expiry_state`
(`none, ok, expiring_soon, expired`), `status, owner, strength {bits,label}, reused_in_my_vault,
warnings, access, request_code, password_changed_at, created_at, updated_at`.

`request_code` is the credential's unguessable identifier used for access requests (`credential_uid`). It is sent
**to the owner only** (`null` for everyone else). It is not a secret: it is the record's encryption context, which
authenticated encryption does not need to hide, and every request still needs an approval.

`warnings` may contain `expired`, `expiring_soon`, `weak_password` (< 36 estimated bits),
`reused_in_my_vault` (owner's own vault only), `older_than_policy_max_age`.

Policy enforcement on write (server-side): password length and symbol rules from the active policy; expiry
must be a future date no later than `max_age_days`; if omitted it defaults to today + `max_age_days`; a rotated
password without an explicit expiry gets a fresh default; `expiry_date: null` is rejected when the policy
has a maximum age.

Tags: up to 10, 1-32 chars of letters, digits, space and `. _ : -`, lower-cased and de-duplicated.
Titles and usernames reject `<`, `>` and control characters.

### Password utilities
| Method | Path | Behaviour |
|---|---|---|
| POST | `/api/vault/password/generate/` | `{length?, lowercase?, uppercase?, digits?, symbols?, exclude_ambiguous?}` -> `{password, strength, policy}`. Default length `max(20, policy.min_length)`. Requests that would violate the policy return `403` with `code` `below_min_length` or `symbols_required`. The password is returned once and never stored, logged or audited |
| POST | `/api/vault/password/check/` | `{password}` -> `{strength {bits,label,issues}, policy_violations, compliant}`; never echoes the password |

Both are rate-limited (30/min per scope). Strength is a heuristic upper bound: it cannot see dictionary words or
keyboard patterns, so human-chosen passwords are over-rated; generated ones are estimated well.

## Reveal, sharing, access requests and notifications (new)
Design, rules and status codes: see [sharing.md](sharing.md). All endpoints need `vault.use`; responses are `no-store`.
Error bodies are `{"detail": "...", "code": "<machine code>"}`.

| Method | Path | Notes |
|---|---|---|
| POST | `/api/vault/credentials/{id}/reveal/` | Full pipeline. Returns `{password, via, view_once, grant_id}`. Throttled 20/min. Blocked by lockdown, the device policy, expired/revoked/consumed grants |
| POST | `/api/vault/notes/{id}/reveal/` | Owner only. Returns `{content, ...}` |
| GET / PATCH | `/api/vault/credentials/{id}/` | Owner **or** holder of a usable grant (PATCH needs EDIT). Includes an `access` hint: `{role, can_view, can_edit, can_share, expires_at, view_once}` |
| GET | `/api/vault/credentials/{id}/shares/` | Owner sees all grants; a delegate sees the grants they issued |
| POST | `/api/vault/credentials/{id}/shares/` | `{grantee_email, can_view?, can_edit?, can_share?, is_view_once?, expires_at? \| expires_in_hours?}`. Owner = direct share, SHARE holder = delegation. Blocked by lockdown |
| GET | `/api/vault/credentials/{id}/shares/tree/` | Owner only; nested delegation tree |
| POST | `/api/vault/shares/{id}/revoke/` | Owner (any grant) or grantor (own grants). Cascades. `{..., grants_revoked}`. Allowed during lockdown |
| GET | `/api/vault/shared-with-me/`, `/api/vault/shared-by-me/` | Usable grants I hold / grants I issued (any status) |
| POST | `/api/vault/access-requests/` | `{credential_uid, reason (10-500), requested_hours (1-168), want_edit?}` |
| GET | `/api/vault/access-requests/` | `?scope=mine` (default) or `?scope=review` (I can decide), `?status=` |
| GET | `/api/vault/access-requests/{id}/` | Requester or an eligible approver; others `404` |
| POST | `.../access-requests/{id}/approve/`, `/reject/`, `/cancel/` | `{note?, hours?}`; cancel is requester-only; decisions are final |
| GET | `/api/notifications/` | Own notifications, newest first, `?unread=true` |
| POST | `/api/notifications/{id}/read/`, `/read-all/` | |
| GET | `/api/notifications/unread-count/` | |

New audit entries: `SHARE` (`direct`, `delegated`), `REVOKE` (`direct`, `cascade`), `REVEAL` (`owner`, `granted`,
`granted_view_once`, or a denial reason such as `grant_consumed`), `ACCESS_REQUEST`, `ACCESS_DECISION`
(`approved`, `rejected`, `cancelled`). Metadata holds ids and permission flags, never secrets.

## Audit events written by this module
| Action | When | `reason_code` |
|---|---|---|
| `CREATE` / `EDIT` (target `service`) | create / field change (no event for a no-op) / deactivate / activate | `created`, `updated`, `deactivated`, `activated` |
| `POLICY_CHANGE` (target `security_policy`) | create / field change / activation | `created`, `updated`, `activated` |

| `CREATE` / `EDIT` (target `credential`, `secure_note`) | create / metadata change / secret rotation (`rotated: true`, no value) / archive / unarchive | `created`, `updated`, `archived`, `unarchived` |

Metadata carries `{"changes": {"field": {"from": old, "to": new}}}` for non-secret fields only. A changed
`username` is recorded as `{"changed": true}` without the value. Passwords and note content are never present.
