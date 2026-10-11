import { act, fireEvent, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Access } from '../lib/types'
import { fail, mockApi, renderPlain } from '../test/utils'
import { ShareDialog } from './ShareDialog'

afterEach(() => vi.restoreAllMocks())

const OWNER: Access = { role: 'owner', can_view: true, can_edit: true, can_share: true, expires_at: null, view_once: false }
const POLICY = { name: 'P', min_length: 12, require_symbols: true, max_age_days: 90, allow_view_once: true, require_device_trust: false, source: 'organization' }
const SHARE = { id: 9, grantee: { id: 2, email: 'bob@acme.example', full_name: 'Bob' } }

function open(access: Access, routes: Record<string, unknown> = {}) {
  const api = mockApi({ 'GET /api/org/security-policies/active/': POLICY, ...routes })
  const onShared = vi.fn()
  const onClose = vi.fn()
  renderPlain(<ShareDialog open onClose={onClose} credentialId={5} access={access} onShared={onShared} />)
  return { api, onShared, onClose }
}

describe('ShareDialog', () => {
  it('shares with the chosen permissions and lease', async () => {
    const { api, onShared } = open(OWNER, { 'POST /api/vault/credentials/5/shares/': SHARE })
    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/colleague's email/i), 'bob@acme.example')
    await user.click(screen.getByLabelText(/edit the credential/i))
    await user.selectOptions(screen.getByLabelText(/access lasts/i), '24')
    await user.click(screen.getByRole('button', { name: 'Share' }))

    await waitFor(() => expect(onShared).toHaveBeenCalled())
    expect(api.find('POST', '/api/vault/credentials/5/shares/')[0].body).toEqual({
      grantee_email: 'bob@acme.example',
      can_view: true,
      can_edit: true,
      can_share: false,
      is_view_once: false,
      expires_in_hours: 24,
    })
  })

  it('one-time view forces view-only and locks the other permissions', async () => {
    open(OWNER)
    const user = userEvent.setup()
    await user.click(screen.getByLabelText(/edit the credential/i))
    await user.click(screen.getByLabelText(/share it onward/i))
    await user.click(screen.getByLabelText(/one-time view/i))
    expect(screen.getByLabelText(/edit the credential/i)).not.toBeChecked()
    expect(screen.getByLabelText(/edit the credential/i)).toBeDisabled()
    expect(screen.getByLabelText(/share it onward/i)).toBeDisabled()
    expect(screen.getByLabelText(/view the secret/i)).toBeChecked()
  })

  it('sends is_view_once only with view-only permissions', async () => {
    const { api, onShared } = open(OWNER, { 'POST /api/vault/credentials/5/shares/': SHARE })
    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/colleague's email/i), 'bob@acme.example')
    await user.click(screen.getByLabelText(/one-time view/i))
    await user.click(screen.getByRole('button', { name: 'Share' }))
    await waitFor(() => expect(onShared).toHaveBeenCalled())
    expect(api.find('POST', '/api/vault/credentials/5/shares/')[0].body).toMatchObject({
      is_view_once: true, can_view: true, can_edit: false, can_share: false,
    })
  })

  it('disables one-time sharing when the organization policy forbids it', async () => {
    open(OWNER, { 'GET /api/org/security-policies/active/': { ...POLICY, allow_view_once: false } })
    await waitFor(() => expect(screen.getByLabelText(/one-time view/i)).toBeDisabled())
    expect(screen.getByText(/turned off by your organization/i)).toBeInTheDocument()
  })

  it('a delegate can only hand on the permissions they hold', async () => {
    open({ role: 'shared', can_view: true, can_edit: false, can_share: true, expires_at: null, view_once: false })
    expect(screen.getByLabelText(/view the secret/i)).toBeEnabled()
    expect(screen.getByLabelText(/edit the credential/i)).toBeDisabled()
    expect(screen.getByLabelText(/share it onward/i)).toBeEnabled()
    expect(screen.getByRole('heading', { name: /delegate access/i })).toBeInTheDocument()
    expect(screen.getByText(/never outlast the share it came from/i)).toBeInTheDocument()
  })

  it.each([
    ['exceeds_upstream_lifetime', 400, /longer than the share it came from/i],
    ['invalid_grantee', 400, /no such active user/i],
    ['delegation_cycle', 400, /already part of this sharing chain/i],
  ])('explains the backend rule %s', async (code, status, message) => {
    const { onShared } = open(OWNER, { 'POST /api/vault/credentials/5/shares/': fail(status, { detail: 'x', code }) })
    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/colleague's email/i), 'bob@acme.example')
    await user.click(screen.getByRole('button', { name: 'Share' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(message)
    expect(onShared).not.toHaveBeenCalled()
  })

  it('blocks nothing client-side that the server should decide: it still submits and shows the 423', async () => {
    open(OWNER, { 'POST /api/vault/credentials/5/shares/': fail(423, { detail: 'locked', code: 'lockdown_active' }) })
    await act(async () => {
      fireEvent.change(screen.getByLabelText(/colleague's email/i), { target: { value: 'bob@acme.example' } })
    })
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Share' }))
    })
    expect(await screen.findByRole('alert')).toHaveTextContent(/emergency lockdown/i)
  })
})
