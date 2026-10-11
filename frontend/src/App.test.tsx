import { screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import App from './App'
import { fail, mockApi, me, page, renderApp } from './test/utils'

afterEach(() => vi.restoreAllMocks())

it('sends anonymous visitors to the login page', async () => {
  mockApi({ 'GET /api/auth/me/': fail(403, { detail: 'x', code: 'not_authenticated' }) })
  renderApp(<App />, { route: '/vault' })
  expect(await screen.findByRole('heading', { name: /sign in to securevault/i })).toBeInTheDocument()
})

it('shows the app shell and dashboard for a signed-in user', async () => {
  mockApi({
    'GET /api/auth/me/': me(),
    'GET /api/notifications/unread-count/': { unread: 2 },
    'GET /api/vault/credentials/': page([], 7),
    'GET /api/vault/shared-with-me/': page([]),
    'GET /api/vault/access-requests/': page([]),
    'GET /api/notifications/': page([]),
    'GET /api/org/security-policies/active/': {
      name: 'Default', min_length: 12, require_symbols: true, max_age_days: 90, allow_view_once: true, require_device_trust: false, source: 'organization',
    },
  })
  renderApp(<App />, { route: '/' })
  expect(await screen.findByText(/welcome, ada lovelace/i)).toBeInTheDocument()
  expect(screen.getByRole('navigation', { name: 'Main' })).toBeInTheDocument()
  expect(await screen.findByText('At least 12 characters', { exact: false })).toBeInTheDocument()
})

it('shows a not-found page for unknown routes', async () => {
  mockApi({ 'GET /api/auth/me/': me(), 'GET /api/notifications/unread-count/': { unread: 0 } })
  renderApp(<App />, { route: '/does/not/exist' })
  expect(await screen.findByRole('heading', { name: /page not found/i })).toBeInTheDocument()
})
