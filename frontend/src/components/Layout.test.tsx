import { act, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import App from '../App'
import { setApiHooks } from '../lib/api'
import { ADMIN_PERMS, fail, me, mockApi, page, renderApp } from '../test/utils'

afterEach(() => {
  vi.restoreAllMocks()
  setApiHooks({})
})

const base = {
  'GET /api/notifications/unread-count/': { unread: 3 },
  'GET /api/vault/credentials/': page([]),
  'GET /api/vault/shared-with-me/': page([]),
  'GET /api/vault/access-requests/': page([]),
  'GET /api/notifications/': page([]),
  'GET /api/org/security-policies/active/': { name: 'P', min_length: 12, require_symbols: true, max_age_days: 90, allow_view_once: true, require_device_trust: false, source: 'organization' },
}

it('an employee sees only the read-only service catalog under Organization, plus the unread badge', async () => {
  mockApi({ ...base, 'GET /api/auth/me/': me() })
  renderApp(<App />)
  const nav = await screen.findByRole('navigation', { name: 'Main' })
  expect(nav).toHaveTextContent('Vault')
  expect(nav).toHaveTextContent('Service catalog')
  for (const hidden of ['Departments', 'Employees', 'Security policies', 'Audit log']) expect(nav).not.toHaveTextContent(hidden)
  expect(await screen.findByLabelText('3 unread')).toBeInTheDocument()
})

it('an administrator sees the administration section', async () => {
  mockApi({ ...base, 'GET /api/auth/me/': me({ roles: ['PLATFORM_ADMIN'], permissions: ADMIN_PERMS }) })
  renderApp(<App />)
  const nav = await screen.findByRole('navigation', { name: 'Main' })
  for (const label of ['Organization', 'Departments', 'Employees', 'Service catalog', 'Security policies', 'Audit log']) {
    expect(nav).toHaveTextContent(label)
  }
  expect(screen.getByText('Platform Administrator')).toBeInTheDocument()
})

it('typing an admin URL as an employee shows a permission screen and never calls the admin API', async () => {
  const api = mockApi({ ...base, 'GET /api/auth/me/': me() })
  renderApp(<App />, { route: '/admin/audit' })
  expect(await screen.findByRole('alert')).toHaveTextContent(/do not have permission/i)
  expect(api.find('GET', '/api/audit/events/')).toHaveLength(0)
})

it('an emergency lockdown (HTTP 423 anywhere) raises a banner that explains what is blocked', async () => {
  mockApi({
    ...base,
    'GET /api/auth/me/': me(),
    'GET /api/vault/credentials/': fail(423, { detail: 'locked', code: 'lockdown_active' }),
  })
  renderApp(<App />, { route: '/vault' })
  const banner = await screen.findByText('Emergency lockdown is active.')
  expect(banner).toBeInTheDocument()
  expect(screen.getByText(/revoke access/i)).toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Dismiss' }))
  expect(screen.queryByText('Emergency lockdown is active.')).toBeNull()
})

it('when the session ends mid-use the user is sent to the login page', async () => {
  mockApi({
    ...base,
    'GET /api/auth/me/': me(),
    'GET /api/vault/credentials/': fail(403, { detail: 'Authentication credentials were not provided.', code: 'not_authenticated' }),
  })
  renderApp(<App />, { route: '/vault' })
  expect(await screen.findByRole('heading', { name: /sign in to securevault/i })).toBeInTheDocument()
})

it('signing out calls the server, then shows the login page', async () => {
  const api = mockApi({ ...base, 'GET /api/auth/me/': me(), 'POST /api/auth/logout/': new Response(null, { status: 204 }) })
  renderApp(<App />)
  await userEvent.click(await screen.findByRole('button', { name: 'Sign out' }))
  expect(await screen.findByRole('heading', { name: /sign in to securevault/i })).toBeInTheDocument()
  expect(api.find('POST', '/api/auth/logout/')).toHaveLength(1)
})

it('the mobile menu toggles the navigation', async () => {
  mockApi({ ...base, 'GET /api/auth/me/': me() })
  renderApp(<App />)
  const toggle = await screen.findByRole('button', { name: 'Toggle navigation' })
  expect(toggle).toHaveAttribute('aria-expanded', 'false')
  await act(async () => toggle.click())
  await waitFor(() => expect(toggle).toHaveAttribute('aria-expanded', 'true'))
})
