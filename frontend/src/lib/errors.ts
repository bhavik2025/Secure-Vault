import { ApiError } from './api'

/** Friendly text for the backend's machine-readable error codes. */
const MESSAGES: Record<string, string> = {
  grant_consumed: 'This one-time access has already been used.',
  grant_revoked: 'Your access to this credential was revoked.',
  grant_expired: 'Your access to this credential has expired.',
  view_not_granted: 'You were not given permission to view the secret.',
  edit_not_granted: 'You were not given permission to edit this credential.',
  share_not_granted: 'You were not given permission to share this credential.',
  no_access: 'Not found, or you do not have access.',
  lockdown_active: 'An emergency lockdown is active. This action is blocked until it is lifted.',
  device_trust_unavailable: 'Your organization requires a trusted device, and device trust cannot be verified yet.',
  record_archived: 'This item is archived. Unarchive it first.',
  decryption_failed: 'The secret could not be decrypted. Contact an administrator.',
  invalid_grantee: 'No such active user in your organization.',
  exceeds_upstream_permissions: 'You cannot grant permissions you do not hold yourself.',
  exceeds_upstream_lifetime: 'A delegated share cannot last longer than the share it came from.',
  max_delegation_depth: 'Delegation is limited to 5 levels.',
  delegation_cycle: 'That person is already part of this sharing chain.',
  view_once_view_only: 'A one-time share can only grant view access.',
  view_once_disabled: "One-time sharing is turned off by your organization's security policy.",
  below_min_length: "That is shorter than your organization's minimum password length.",
  symbols_required: "Your organization's policy requires symbols.",
  expiry_in_past: 'The expiry must be in the future.',
  no_permission: 'Grant at least one of view, edit or share.',
  own_credential: 'You own this credential.',
  not_authenticated: 'Your session has ended. Please sign in again.',
}

export function errorMessage(err: unknown, fallback = 'Something went wrong. Please try again.'): string {
  if (err instanceof ApiError) {
    if (err.code && MESSAGES[err.code]) return MESSAGES[err.code]
    if (err.status === 429) return 'Too many requests. Please wait a moment and try again.'
    if (err.status === 404) return MESSAGES.no_access
    if (err.status >= 500) return fallback
    if (err.detail) return err.detail
    const fields = fieldErrors(err)
    const first = Object.values(fields)[0]
    if (first) return first
    return fallback
  }
  return 'Cannot reach the SecureVault server. Check your connection.'
}

/** Network failures, server errors and throttling may succeed on retry; 4xx decisions (revoked, consumed,
 *  forbidden, not found) will not, so offering "Retry" for them would only mislead. */
export function isTransient(err: unknown): boolean {
  if (!(err instanceof ApiError)) return true
  return err.status >= 500 || err.status === 429
}

/** Per-field validation messages from a DRF 400 body: `{ field: ["msg", ...] }`. */
export function fieldErrors(err: unknown): Record<string, string> {
  const out: Record<string, string> = {}
  if (!(err instanceof ApiError) || err.status !== 400) return out
  const body = err.body
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    if (Array.isArray(body) && typeof body[0] === 'string') out.non_field_errors = body[0]
    return out
  }
  for (const [key, value] of Object.entries(body as Record<string, unknown>)) {
    if (key === 'code' || key === 'detail') continue // general message + machine code, not a form field
    if (Array.isArray(value) && value.length && typeof value[0] === 'string') out[key] = value.join(' ')
    else if (typeof value === 'string') out[key] = value
  }
  return out
}
