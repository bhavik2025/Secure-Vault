export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso.length === 10 ? `${iso}T00:00:00` : iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleDateString(undefined, { dateStyle: 'medium' })
}

/** "in 3 days", "in 2 hours", "5 minutes ago". */
export function relativeTime(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return '—'
  const diff = new Date(iso).getTime() - now
  if (Number.isNaN(diff)) return '—'
  const abs = Math.abs(diff)
  const units: [number, string][] = [
    [86_400_000, 'day'],
    [3_600_000, 'hour'],
    [60_000, 'minute'],
  ]
  for (const [ms, name] of units) {
    if (abs >= ms) {
      const n = Math.floor(abs / ms)
      const label = `${n} ${name}${n === 1 ? '' : 's'}`
      return diff >= 0 ? `in ${label}` : `${label} ago`
    }
  }
  return diff >= 0 ? 'in under a minute' : 'just now'
}

export const CATEGORY_LABELS: Record<string, string> = {
  DATABASE: 'Database',
  CLOUD: 'Cloud platform',
  SAAS: 'SaaS application',
  SOURCE_CONTROL: 'Source control / CI',
  INFRASTRUCTURE: 'Infrastructure / server',
  MONITORING: 'Monitoring / logging',
  OTHER: 'Other',
}

export const ROLE_LABELS: Record<string, string> = {
  PLATFORM_ADMIN: 'Platform Administrator',
  SECURITY_ADMIN: 'Security Administrator',
  DEPARTMENT_MANAGER: 'Department Manager',
  EMPLOYEE: 'Employee',
}

export const WARNING_LABELS: Record<string, string> = {
  expired: 'Expired',
  expiring_soon: 'Expiring soon',
  weak_password: 'Weak password',
  reused_in_my_vault: 'Reused in your vault',
  older_than_policy_max_age: 'Older than policy maximum',
}
