import { useEffect, useState } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'
import { api } from '../lib/api'
import { ROLE_LABELS } from '../lib/format'
import { Button } from './ui'

interface NavItem {
  to: string
  label: string
  permission?: string
  end?: boolean
}

const MAIN: NavItem[] = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/vault', label: 'Vault' },
  { to: '/notes', label: 'Secure notes' },
  { to: '/shared', label: 'Shared' },
  { to: '/requests', label: 'Access requests' },
  { to: '/notifications', label: 'Notifications' },
]

const ADMIN: NavItem[] = [
  { to: '/admin/departments', label: 'Departments', permission: 'departments.view' },
  { to: '/admin/employees', label: 'Employees', permission: 'users.view' },
  { to: '/admin/services', label: 'Service catalog', permission: 'services.view' },
  { to: '/admin/policies', label: 'Security policies', permission: 'policies.view' },
  { to: '/admin/audit', label: 'Audit log', permission: 'audit.view' },
]

export const NOTIFICATIONS_CHANGED = 'sv:notifications-changed'

function useUnreadCount(): number {
  const [unread, setUnread] = useState(0)
  useEffect(() => {
    let alive = true
    const load = () =>
      api
        .get<{ unread: number }>('/notifications/unread-count/')
        .then((r) => alive && setUnread(r.unread))
        .catch(() => undefined)
    void load()
    const id = setInterval(load, 60_000)
    window.addEventListener(NOTIFICATIONS_CHANGED, load)
    return () => {
      alive = false
      clearInterval(id)
      window.removeEventListener(NOTIFICATIONS_CHANGED, load)
    }
  }, [])
  return unread
}

const linkClass = ({ isActive }: { isActive: boolean }) =>
  `flex items-center justify-between rounded-lg px-3 py-2 text-sm font-medium ${
    isActive
      ? 'bg-indigo-50 text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300'
      : 'text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800'
  }`

export function Layout() {
  const { user, can, logout, lockdown, dismissLockdown } = useAuth()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const unread = useUnreadCount()
  const admin = ADMIN.filter((i) => !i.permission || can(i.permission))

  async function signOut() {
    await logout()
    navigate('/login', { replace: true })
  }

  const nav = (
    <nav aria-label="Main" className="space-y-6">
      <ul className="space-y-1">
        {MAIN.map((i) => (
          <li key={i.to}>
            <NavLink to={i.to} end={i.end} className={linkClass} onClick={() => setOpen(false)}>
              {i.label}
              {i.to === '/notifications' && unread > 0 && (
                <span aria-label={`${unread} unread`} className="rounded-full bg-red-600 px-2 py-0.5 text-xs text-white">
                  {unread}
                </span>
              )}
            </NavLink>
          </li>
        ))}
      </ul>
      {admin.length > 0 && (
        <div>
          <p className="mb-2 px-3 text-xs font-semibold uppercase tracking-wide text-slate-400">Organization</p>
          <ul className="space-y-1">
            {admin.map((i) => (
              <li key={i.to}>
                <NavLink to={i.to} className={linkClass} onClick={() => setOpen(false)}>
                  {i.label}
                </NavLink>
              </li>
            ))}
          </ul>
        </div>
      )}
    </nav>
  )

  return (
    <div className="min-h-screen lg:flex">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-white focus:p-2">
        Skip to content
      </a>

      <aside
        className={`${open ? 'block' : 'hidden'} fixed inset-y-0 left-0 z-40 w-64 overflow-y-auto border-r border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900 lg:static lg:block`}
      >
        <div className="mb-6 px-3 text-lg font-semibold text-indigo-600">SecureVault</div>
        {nav}
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between gap-3 border-b border-slate-200 bg-white px-4 py-3 dark:border-slate-800 dark:bg-slate-900">
          <div className="flex items-center gap-3">
            <button
              type="button"
              className="rounded-lg p-2 ring-1 ring-slate-300 lg:hidden dark:ring-slate-600"
              aria-label="Toggle navigation"
              aria-expanded={open}
              onClick={() => setOpen((o) => !o)}
            >
              <span aria-hidden>☰</span>
            </button>
            <span className="text-sm text-slate-500">{user?.organization.name}</span>
          </div>
          <div className="flex items-center gap-3">
            <NavLink to="/profile" className="text-right text-sm">
              <span className="block font-medium text-slate-900 dark:text-slate-100">{user?.full_name || user?.email}</span>
              <span className="block text-xs text-slate-500">{user?.roles.map((r) => ROLE_LABELS[r] ?? r).join(', ') || 'No role'}</span>
            </NavLink>
            <Button variant="secondary" onClick={() => void signOut()}>
              Sign out
            </Button>
          </div>
        </header>

        {lockdown && (
          <div role="alert" className="flex items-center justify-between gap-3 bg-red-600 px-4 py-3 text-sm text-white">
            <span>
              <strong>Emergency lockdown is active.</strong> Revealing secrets, creating or editing credentials and new sharing are
              blocked by the server until it is lifted. You can still view metadata and revoke access.
            </span>
            <button type="button" className="underline" onClick={dismissLockdown}>
              Dismiss
            </button>
          </div>
        )}

        <main id="main" className="mx-auto w-full max-w-6xl flex-1 px-4 py-8">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
