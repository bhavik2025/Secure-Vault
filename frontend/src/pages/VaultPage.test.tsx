import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { afterEach, expect, it, vi } from 'vitest'
import { cred } from '../test/factories'
import { fail, mockApi, page, renderPlain } from '../test/utils'
import { VaultPage } from './VaultPage'

afterEach(() => vi.restoreAllMocks())

const shell = (
  <Routes>
    <Route path="/vault" element={<VaultPage />} />
    <Route path="/vault/:id" element={<p>DETAIL PAGE</p>} />
  </Routes>
)

it('lists credentials with health badges and masked metadata only', async () => {
  mockApi({
    'GET /api/vault/credentials/': page([
      cred(),
      cred({ id: 2, title: 'Old key', warnings: ['expired', 'weak_password', 'reused_in_my_vault'], service_name: null, username: '' }),
    ]),
  })
  renderPlain(shell, { route: '/vault' })
  expect(await screen.findByRole('link', { name: 'Prod DB' })).toHaveAttribute('href', '/vault/1')
  expect(screen.getByText('Healthy')).toBeInTheDocument()
  const table = screen.getByRole('table', { name: 'Your credentials' })
  expect(within(table).getByText('Expired')).toBeInTheDocument()
  expect(within(table).getByText('Weak password')).toBeInTheDocument()
  expect(within(table).getByText('Reused in your vault')).toBeInTheDocument()
  expect(screen.queryByText(/password:/i)).toBeNull()
})

it('has an empty state, an error state with retry, and a loading state', async () => {
  let call = 0
  mockApi({
    'GET /api/vault/credentials/': () => (++call === 1 ? fail(500, null) : page([])),
  })
  renderPlain(shell, { route: '/vault' })
  expect(screen.getByText(/loading credentials/i)).toBeInTheDocument()
  expect(await screen.findByRole('alert')).toHaveTextContent(/something went wrong/i)
  await userEvent.click(screen.getByRole('button', { name: 'Retry' }))
  expect(await screen.findByText('Your vault is empty')).toBeInTheDocument()
})

it('sends search and filters to the server (debounced) and says when nothing matches', async () => {
  const api = mockApi({
    'GET /api/vault/credentials/': ({ url }: { url: URL }) => (url.searchParams.get('q') === 'zzz' ? page([]) : page([cred()])),
  })
  renderPlain(shell, { route: '/vault' })
  await screen.findByText('Prod DB')
  const user = userEvent.setup()
  await user.type(screen.getByLabelText('Search'), 'zzz')
  await user.selectOptions(screen.getByLabelText('Category'), 'DATABASE')
  expect(await screen.findByText('No credentials match your filters', {}, { timeout: 3000 })).toBeInTheDocument()
  const last = api.find('GET', '/api/vault/credentials/').at(-1)!
  expect(last.query).toMatchObject({ q: 'zzz', category: 'DATABASE', status: 'ACTIVE', ordering: 'title', page: '1' })
  expect(api.find('GET', '/api/vault/credentials/').filter((c) => c.query.q?.length === 1)).toHaveLength(0) // debounce: no per-keystroke calls
})

it('paginates and resets to page 1 when a filter changes', async () => {
  const api = mockApi({ 'GET /api/vault/credentials/': page([cred()], 60) })
  renderPlain(shell, { route: '/vault' })
  await screen.findByText('Prod DB')
  await userEvent.click(screen.getByRole('button', { name: 'Next' }))
  await waitFor(() => expect(api.find('GET', '/api/vault/credentials/').at(-1)!.query.page).toBe('2'))
  await userEvent.selectOptions(screen.getByLabelText('Show'), 'ARCHIVED')
  await waitFor(() => expect(api.find('GET', '/api/vault/credentials/').at(-1)!.query).toMatchObject({ status: 'ARCHIVED', page: '1' }))
})

it('opens the new-credential form', async () => {
  mockApi({
    'GET /api/vault/credentials/': page([]),
    'GET /api/org/services/': page([]),
    'GET /api/org/security-policies/active/': { name: 'P', min_length: 12, require_symbols: true, max_age_days: 90, allow_view_once: true, require_device_trust: false, source: 'organization' },
  })
  renderPlain(shell, { route: '/vault' })
  await userEvent.click(await screen.findByRole('button', { name: 'New credential' }))
  expect(await screen.findByRole('heading', { name: 'New credential' })).toBeInTheDocument()
})
