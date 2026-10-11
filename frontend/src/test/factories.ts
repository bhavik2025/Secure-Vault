import type { Credential } from '../lib/types'

export function cred(over: Partial<Credential> = {}): Credential {
  return {
    id: 1, title: 'Prod DB', service: 3, service_name: 'AWS', username: 'svc', password_masked: '\u2022'.repeat(12), has_password: true,
    category: 'DATABASE', tags: ['prod'], expiry_date: '2026-12-01', expiry_state: 'ok', status: 'ACTIVE',
    owner: { id: 1, email: 'ada@acme.example', full_name: 'Ada' }, strength: { bits: 90, label: 'STRONG' }, reused_in_my_vault: false,
    warnings: [], access: { role: 'owner', can_view: true, can_edit: true, can_share: true, expires_at: null, view_once: false },
    request_code: '3f0c2a9e-6d1b-4f7e-9a51-2c8d4e6f7a10',
    password_changed_at: '2026-01-01T00:00:00Z', created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', ...over,
  }
}