import { Link } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'
import { Card, ErrorBanner, LoadingBlock, PageHeader } from '../components/ui'
import { useResource } from '../hooks/useResource'
import { api } from '../lib/api'
import type { AppNotification, EffectivePolicy, Page } from '../lib/types'

interface Counts {
  credentials: number
  expired: number
  soon: number
  sharedWithMe: number
  toReview: number
  unread: number
  recent: AppNotification[]
  policy: EffectivePolicy
}

async function load(): Promise<Counts> {
  const [credentials, expired, soon, shared, review, unread, recent, policy] = await Promise.all([
    api.get<Page<unknown>>('/vault/credentials/'),
    api.get<Page<unknown>>('/vault/credentials/', { expiry: 'expired' }),
    api.get<Page<unknown>>('/vault/credentials/', { expiry: 'soon' }),
    api.get<Page<unknown>>('/vault/shared-with-me/'),
    api.get<Page<unknown>>('/vault/access-requests/', { scope: 'review', status: 'PENDING' }),
    api.get<{ unread: number }>('/notifications/unread-count/'),
    api.get<Page<AppNotification>>('/notifications/'),
    api.get<EffectivePolicy>('/org/security-policies/active/'),
  ])
  return {
    credentials: credentials.count,
    expired: expired.count,
    soon: soon.count,
    sharedWithMe: shared.count,
    toReview: review.count,
    unread: unread.unread,
    recent: recent.results.slice(0, 5),
    policy,
  }
}

function Stat({ label, value, to, tone = 'text-slate-900 dark:text-slate-100' }: { label: string; value: number; to: string; tone?: string }) {
  return (
    <Link
      to={to}
      className="block rounded-xl bg-white p-5 shadow-sm ring-1 ring-slate-200 transition hover:ring-indigo-400 dark:bg-slate-900 dark:ring-slate-800"
    >
      <p className="text-sm text-slate-500">{label}</p>
      <p className={`mt-1 text-3xl font-semibold ${tone}`}>{value}</p>
    </Link>
  )
}

export function DashboardPage() {
  const { user } = useAuth()
  const res = useResource(load, [])
  const d = res.data
  return (
    <>
      <PageHeader title={`Welcome, ${user?.full_name || user?.email}`} description={`${user?.organization.name} · security overview`} />
      <ErrorBanner error={res.error} onRetry={res.reload} />
      {res.loading && !d && <LoadingBlock />}
      {d && (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <Stat label="Credentials in your vault" value={d.credentials} to="/vault" />
            <Stat label="Expiring within 14 days" value={d.soon} to="/vault" tone={d.soon ? 'text-amber-600' : undefined} />
            <Stat label="Expired" value={d.expired} to="/vault" tone={d.expired ? 'text-red-600' : undefined} />
            <Stat label="Shared with you" value={d.sharedWithMe} to="/shared" />
            <Stat label="Requests awaiting your decision" value={d.toReview} to="/requests" tone={d.toReview ? 'text-indigo-600' : undefined} />
            <Stat label="Unread notifications" value={d.unread} to="/notifications" />
          </div>

          <div className="mt-6 grid gap-6 lg:grid-cols-2">
            <Card title="Recent notifications">
              {d.recent.length === 0 ? (
                <p className="text-sm text-slate-500">Nothing new.</p>
              ) : (
                <ul className="space-y-3">
                  {d.recent.map((n) => (
                    <li key={n.id} className="text-sm">
                      <p className={n.is_read ? 'text-slate-700 dark:text-slate-300' : 'font-medium text-slate-900 dark:text-slate-100'}>{n.title}</p>
                      <p className="text-slate-500">{n.message}</p>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
            <Card title="Your organization's security policy">
              <ul className="space-y-1 text-sm text-slate-700 dark:text-slate-300">
                <li>Passwords: at least {d.policy.min_length} characters{d.policy.require_symbols ? ', with a symbol' : ''}</li>
                <li>{d.policy.max_age_days ? `Credentials expire after at most ${d.policy.max_age_days} days` : 'Credentials may be kept without an expiry'}</li>
                <li>One-time sharing: {d.policy.allow_view_once ? 'allowed' : 'turned off'}</li>
                <li>Trusted device required: {d.policy.require_device_trust ? 'yes' : 'no'}</li>
              </ul>
            </Card>
          </div>
        </>
      )}
    </>
  )
}
