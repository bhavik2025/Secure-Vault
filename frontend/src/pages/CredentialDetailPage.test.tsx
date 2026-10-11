import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { afterEach, expect, it, vi } from 'vitest'
import type { Access, Share } from '../lib/types'
import { fail, mockApi, page, renderPlain } from '../test/utils'
import { CredentialDetailPage } from './CredentialDetailPage'
import { cred } from '../test/factories'

afterEach(() => vi.restoreAllMocks())

const shell = (
  <Routes>
    <Route path="/vault/:id" element={<CredentialDetailPage />} />
    <Route path="/vault" element={<p>VAULT LIST</p>} />
  </Routes>
)
const person = (email: string) => ({ id: 2, email, full_name: '' })
const share = (over: Partial<Share> = {}): Share => ({
  id: 10, credential: 1, credential_title: 'Prod DB', parent: null, grantor: person('ada@acme.example'), grantee: person('bob@acme.example'),
  can_view: true, can_edit: false, can_share: false, expires_at: null, is_view_once: false, status: 'ACTIVE', burned_at: null,
  revoked_at: null, revoked_via_cascade: false, depth: 1, created_at: '2026-01-01T00:00:00Z', ...over,
})
const shared = (a: Partial<Access>) =>
  cred({
    access: { role: 'shared', can_view: true, can_edit: false, can_share: false, expires_at: null, view_once: false, ...a },
    owner: person('owner@acme.example'),
    request_code: null, // the API only sends it to the owner
  })

it('owner view: details, masked secret, sharing panel and actions', async () => {
  mockApi({
    'GET /api/vault/credentials/1/': cred(),
    'GET /api/vault/credentials/1/shares/': page([share()]),
    'GET /api/vault/credentials/1/shares/tree/': { credential: 1, tree: [] },
  })
  renderPlain(shell, { route: '/vault/1' })
  expect(await screen.findByRole('heading', { name: 'Prod DB' })).toBeInTheDocument()
  expect(screen.getByLabelText('Password (hidden)')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Edit' })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Archive' })).toBeInTheDocument()
  expect(await screen.findByText('bob@acme.example')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Share' })).toBeInTheDocument()
  expect(screen.getByText('3f0c2a9e-6d1b-4f7e-9a51-2c8d4e6f7a10')).toBeInTheDocument()
  expect(screen.getByText(/it is not a secret/i)).toBeInTheDocument()
})

it('view-only recipient: no edit, no archive, no sharing panel, and an explanatory badge', async () => {
  mockApi({ 'GET /api/vault/credentials/1/': shared({}) })
  renderPlain(shell, { route: '/vault/1' })
  await screen.findByRole('heading', { name: 'Prod DB' })
  expect(screen.getByText('Shared with you')).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Edit' })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Archive' })).toBeNull()
  expect(screen.queryByText('Sharing')).toBeNull()
  expect(screen.getByLabelText('Password (hidden)')).toBeInTheDocument()
  expect(screen.queryByText('Access request ID')).toBeNull()
})

it('edit-only recipient can edit but is told they cannot view the secret', async () => {
  mockApi({ 'GET /api/vault/credentials/1/': shared({ can_view: false, can_edit: true }) })
  renderPlain(shell, { route: '/vault/1' })
  await screen.findByRole('heading', { name: 'Prod DB' })
  expect(screen.getByRole('button', { name: 'Edit' })).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Reveal' })).toBeNull()
  expect(screen.getByText(/not given permission to view the secret/i)).toBeInTheDocument()
})

it('delegate with SHARE sees the delegation panel (not the owner tree)', async () => {
  const api = mockApi({
    'GET /api/vault/credentials/1/': shared({ can_share: true }),
    'GET /api/vault/credentials/1/shares/': page([]),
  })
  renderPlain(shell, { route: '/vault/1' })
  expect(await screen.findByText('Access you have delegated')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Delegate' })).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Delegation tree' })).toBeNull()
  expect(api.find('GET', '/api/vault/credentials/1/shares/tree/')).toHaveLength(0)
})

it('one-time recipient is warned before spending the single reveal', async () => {
  const api = mockApi({ 'GET /api/vault/credentials/1/': shared({ view_once: true }) })
  renderPlain(shell, { route: '/vault/1' })
  expect(await screen.findByText('One-time view')).toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Reveal' }))
  expect(await screen.findByText(/can never be revealed again/i)).toBeInTheDocument()
  expect(api.find('POST', '/api/vault/credentials/1/reveal/')).toHaveLength(0)
})

it.each([
  ['grant_revoked', 403, /revoked/i],
  ['grant_expired', 403, /expired/i],
  ['grant_consumed', 410, /already been used/i],
  ['no_access', 404, /not found/i],
])('explains why access is gone (%s)', async (code, status, message) => {
  mockApi({ 'GET /api/vault/credentials/1/': fail(status, { detail: 'x', code }) })
  renderPlain(shell, { route: '/vault/1' })
  expect(await screen.findByRole('alert')).toHaveTextContent(message)
  expect(screen.getByRole('link', { name: /back to your vault/i })).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull() // retrying a revoked/consumed grant cannot help
})

it('revoking asks for confirmation, warns about cascading, and reports how many people lost access', async () => {
  const api = mockApi({
    'GET /api/vault/credentials/1/': cred(),
    'GET /api/vault/credentials/1/shares/': page([share()]),
    'GET /api/vault/credentials/1/shares/tree/': { credential: 1, tree: [] },
    'POST /api/vault/shares/10/revoke/': { ...share({ status: 'REVOKED' }), grants_revoked: 3 },
  })
  renderPlain(shell, { route: '/vault/1' })
  await userEvent.click(await screen.findByRole('button', { name: /revoke access for bob@acme.example/i }))
  const dialog = await screen.findByRole('dialog')
  expect(within(dialog).getByText(/anyone they passed this access on to will lose it too/i)).toBeInTheDocument()
  expect(api.find('POST', '/api/vault/shares/10/revoke/')).toHaveLength(0)
  await userEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }))
  expect(await screen.findByText(/revoked for 3 people/i)).toBeInTheDocument()
})

it('archiving requires confirmation and warns that the secret becomes unavailable', async () => {
  const api = mockApi({
    'GET /api/vault/credentials/1/': cred(),
    'GET /api/vault/credentials/1/shares/': page([]),
    'GET /api/vault/credentials/1/shares/tree/': { credential: 1, tree: [] },
    'POST /api/vault/credentials/1/archive/': cred({ status: 'ARCHIVED' }),
  })
  renderPlain(shell, { route: '/vault/1' })
  await userEvent.click(await screen.findByRole('button', { name: 'Archive' }))
  expect(await screen.findByText(/can no longer be revealed/i)).toBeInTheDocument()
  expect(api.find('POST', '/api/vault/credentials/1/archive/')).toHaveLength(0)
  await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Archive' }))
  await waitFor(() => expect(api.find('POST', '/api/vault/credentials/1/archive/')).toHaveLength(1))
})

it('an archived credential offers Restore, no secret and no sharing', async () => {
  mockApi({ 'GET /api/vault/credentials/1/': cred({ status: 'ARCHIVED' }) })
  renderPlain(shell, { route: '/vault/1' })
  expect(await screen.findByRole('button', { name: 'Restore' })).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Reveal' })).toBeNull()
  expect(screen.getByText(/restore this credential to reveal/i)).toBeInTheDocument()
  expect(screen.queryByText('Sharing')).toBeNull()
})
