// Mirrors the backend API contract (docs/api.md). Secrets never appear in these types except
// RevealResponse, which is held only in component state and never persisted.

export interface Page<T> {
  count: number
  next: string | null
  previous: string | null
  results: T[]
}

export interface Person {
  id: number
  email: string
  full_name: string
}

export interface Me extends Person {
  organization: { id: number; name: string }
  department: { id: number; name: string } | null
  roles: string[]
  permissions: string[]
}

export type Category =
  | 'DATABASE'
  | 'CLOUD'
  | 'SAAS'
  | 'SOURCE_CONTROL'
  | 'INFRASTRUCTURE'
  | 'MONITORING'
  | 'OTHER'

export const CATEGORIES: { value: Category; label: string }[] = [
  { value: 'DATABASE', label: 'Database' },
  { value: 'CLOUD', label: 'Cloud platform' },
  { value: 'SAAS', label: 'SaaS application' },
  { value: 'SOURCE_CONTROL', label: 'Source control / CI' },
  { value: 'INFRASTRUCTURE', label: 'Infrastructure / server' },
  { value: 'MONITORING', label: 'Monitoring / logging' },
  { value: 'OTHER', label: 'Other' },
]

export interface Access {
  role: 'owner' | 'shared'
  can_view: boolean
  can_edit: boolean
  can_share: boolean
  expires_at: string | null
  view_once: boolean
}

export interface Credential {
  id: number
  title: string
  service: number | null
  service_name: string | null
  username: string
  password_masked: string
  has_password: boolean
  category: Category
  tags: string[]
  expiry_date: string | null
  expiry_state: 'none' | 'ok' | 'expiring_soon' | 'expired'
  status: 'ACTIVE' | 'ARCHIVED'
  owner: Person
  strength: { bits: number; label: string }
  reused_in_my_vault: boolean
  warnings: string[]
  access: Access
  /** Owner only: the unguessable ID colleagues use to request access. Not a secret. */
  request_code: string | null
  password_changed_at: string
  created_at: string
  updated_at: string
}

export interface SecureNote {
  id: number
  title: string
  content_masked: string
  has_content: boolean
  category: Category
  tags: string[]
  status: 'ACTIVE' | 'ARCHIVED'
  owner: Person
  created_at: string
  updated_at: string
}

export interface RevealResponse {
  password?: string
  content?: string
  via: 'owner' | 'grant'
  view_once: boolean
  grant_id: number | null
}

export interface Share {
  id: number
  credential: number
  credential_title: string
  parent: number | null
  grantor: Person
  grantee: Person
  can_view: boolean
  can_edit: boolean
  can_share: boolean
  expires_at: string | null
  is_view_once: boolean
  status: 'ACTIVE' | 'EXPIRED' | 'REVOKED' | 'CONSUMED'
  burned_at: string | null
  revoked_at: string | null
  revoked_via_cascade: boolean
  depth: number
  created_at: string
  grants_revoked?: number
}

export interface ShareTreeNode {
  id: number
  grantor: string
  grantee: string
  view: boolean
  edit: boolean
  share: boolean
  view_once: boolean
  expires_at: string | null
  status: Share['status']
  children: ShareTreeNode[]
}

export interface AccessRequest {
  id: number
  credential_uid: string
  credential_title: string
  requester: Person
  reason: string
  requested_hours: number
  want_edit: boolean
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'CANCELLED' | 'EXPIRED'
  decided_by: Person | null
  decided_at: string | null
  decision_note: string
  resulting_share: number | null
  can_decide: boolean
  created_at: string
}

export interface AppNotification {
  id: number
  type: string
  title: string
  message: string
  priority: 'LOW' | 'NORMAL' | 'HIGH'
  is_read: boolean
  related_type: string
  related_id: string
  created_at: string
}

export interface ServiceEntry {
  id: number
  name: string
  category: Category
  base_url: string
  icon_url: string
  default_port: number | null
  status: 'ACTIVE' | 'INACTIVE'
  created_at: string
  updated_at: string
}

export interface SecurityPolicy {
  id: number
  name: string
  min_length: number
  require_symbols: boolean
  max_age_days: number | null
  allow_view_once: boolean
  require_device_trust: boolean
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface EffectivePolicy {
  name: string
  min_length: number
  require_symbols: boolean
  max_age_days: number | null
  allow_view_once: boolean
  require_device_trust: boolean
  source: string
}

export interface Department {
  id: number
  name: string
  code: string
  head: number | null
  status: 'ACTIVE' | 'INACTIVE'
  created_at: string
}

export interface Employee {
  id: number
  email: string
  full_name: string
  department: number | null
  status: 'INVITED' | 'ACTIVE' | 'SUSPENDED' | 'DEACTIVATED'
  roles: string[]
  last_login: string | null
}

export interface AuditEventRow {
  id: number
  created_at: string
  actor_email: string
  action: string
  outcome: 'SUCCESS' | 'DENIED' | 'FAILURE'
  target_type: string
  target_id: string
  reason_code: string
  ip_address: string | null
  request_id: string
}

export interface Strength {
  bits: number
  label: string
  issues: string[]
}

export interface PasswordCheck {
  strength: Strength
  policy_violations: string[]
  compliant: boolean
}

export interface GeneratedPassword {
  password: string
  strength: Strength
  policy: { min_length: number; require_symbols: boolean; max_age_days: number | null }
}
