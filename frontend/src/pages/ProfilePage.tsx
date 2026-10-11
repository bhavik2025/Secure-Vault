import { useAuth } from '../auth/AuthContext'
import { Badge, Card, PageHeader } from '../components/ui'
import { ROLE_LABELS } from '../lib/format'

export function ProfilePage() {
  const { user } = useAuth()
  if (!user) return null
  return (
    <>
      <PageHeader title="Profile and security" />
      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Account">
          <dl className="space-y-2 text-sm">
            <div className="flex justify-between"><dt className="text-slate-500">Name</dt><dd>{user.full_name || '—'}</dd></div>
            <div className="flex justify-between"><dt className="text-slate-500">Email</dt><dd>{user.email}</dd></div>
            <div className="flex justify-between"><dt className="text-slate-500">Organization</dt><dd>{user.organization.name}</dd></div>
            <div className="flex justify-between"><dt className="text-slate-500">Department</dt><dd>{user.department?.name ?? '—'}</dd></div>
            <div className="flex justify-between gap-4">
              <dt className="text-slate-500">Roles</dt>
              <dd className="flex flex-wrap justify-end gap-1">
                {user.roles.length ? user.roles.map((r) => <Badge key={r} tone="info">{ROLE_LABELS[r] ?? r}</Badge>) : '—'}
              </dd>
            </div>
          </dl>
        </Card>
        <Card title="Session security">
          <ul className="list-disc space-y-2 pl-5 text-sm text-slate-600 dark:text-slate-300">
            <li>Your session ends after 30 minutes of inactivity.</li>
            <li>Secrets are masked by default and hide again 30 seconds after you reveal them.</li>
            <li>Copied secrets are cleared from the clipboard after 30 seconds on a best-effort basis. Browsers may prevent this, so do not rely on it.</li>
            <li>Nothing secret is ever stored in your browser.</li>
          </ul>
        </Card>
        <Card title="What you are allowed to do">
          <p className="mb-3 text-sm text-slate-500">
            These permissions come from your roles. They only decide which screens are shown; the server checks every action.
          </p>
          <ul className="flex flex-wrap gap-1.5">
            {user.permissions.map((p) => (
              <li key={p}><Badge>{p}</Badge></li>
            ))}
          </ul>
        </Card>
      </div>
    </>
  )
}
