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

## Audit events written by this module
| Action | When | `reason_code` |
|---|---|---|
| `CREATE` / `EDIT` (target `service`) | create / field change (no event for a no-op) / deactivate / activate | `created`, `updated`, `deactivated`, `activated` |
| `POLICY_CHANGE` (target `security_policy`) | create / field change / activation | `created`, `updated`, `activated` |

Metadata carries `{"changes": {"field": {"from": old, "to": new}}}` for non-secret fields only.
