import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Credential } from '../lib/types'
import { fail, mockApi, page, renderPlain } from '../test/utils'
import { CredentialFormModal } from './CredentialFormModal'

afterEach(() => vi.restoreAllMocks())

const POLICY = { name: 'P', min_length: 12, require_symbols: true, max_age_days: 90, allow_view_once: true, require_device_trust: false, source: 'organization' }
const SERVICES = page([{ id: 3, name: 'AWS', category: 'CLOUD', base_url: 'https://aws.amazon.com', icon_url: '', default_port: null, status: 'ACTIVE', created_at: '', updated_at: '' }])
const SAVED = { id: 11, title: 'Prod DB' }
const PW = 'Zx9#kLm2$Qw8!'

function routes(extra: Record<string, unknown> = {}) {
  return { 'GET /api/org/services/': SERVICES, 'GET /api/org/security-policies/active/': POLICY, ...extra }
}

describe('CredentialFormModal (create)', () => {
  it('shows the policy requirements and sends a clean payload', async () => {
    const api = mockApi(routes({ 'POST /api/vault/credentials/': SAVED }))
    const onSaved = vi.fn()
    renderPlain(<CredentialFormModal open onClose={vi.fn()} onSaved={onSaved} />)
    expect(await screen.findByText(/at least 12 characters including a symbol/i)).toBeInTheDocument()

    const user = userEvent.setup()
    await user.type(screen.getByLabelText('Title'), 'Prod DB')
    await user.type(screen.getByLabelText('Username'), 'svc_app')
    await user.type(screen.getByLabelText('Password'), PW)
    await user.type(screen.getByLabelText('Tags'), 'prod, db ,')
    await user.click(screen.getByRole('button', { name: 'Create credential' }))

    await waitFor(() => expect(onSaved).toHaveBeenCalledWith(SAVED))
    expect(api.find('POST', '/api/vault/credentials/')[0].body).toEqual({
      title: 'Prod DB', username: 'svc_app', password: PW, category: 'OTHER', tags: ['prod', 'db'],
    }) // no service / expiry keys when left blank: the server applies the policy default
  })

  it('masks the password until the user chooses to show it', async () => {
    mockApi(routes())
    renderPlain(<CredentialFormModal open onClose={vi.fn()} onSaved={vi.fn()} />)
    const field = await screen.findByLabelText('Password')
    expect(field).toHaveAttribute('type', 'password')
    await userEvent.click(screen.getByRole('button', { name: 'Show' }))
    expect(field).toHaveAttribute('type', 'text')
  })

  it('generates a password on the server and shows its strength', async () => {
    mockApi(
      routes({
        'POST /api/vault/password/generate/': {
          password: 'Gen3rated!Pass#word', strength: { bits: 110, label: 'VERY_STRONG', issues: [] },
          policy: { min_length: 12, require_symbols: true, max_age_days: 90 },
        },
      }),
    )
    renderPlain(<CredentialFormModal open onClose={vi.fn()} onSaved={vi.fn()} />)
    await userEvent.click(await screen.findByRole('button', { name: 'Generate' }))
    await waitFor(() => expect(screen.getByLabelText('Password')).toHaveValue('Gen3rated!Pass#word'))
    expect(screen.getByLabelText('Password')).toHaveAttribute('type', 'text')
    expect(await screen.findByText(/very strong/i)).toBeInTheDocument()
    expect(screen.getByText(/estimate/i)).toBeInTheDocument()
  })

  it('checks the password against policy while typing (debounced) and lists violations', async () => {
    const api = mockApi(
      routes({
        'POST /api/vault/password/check/': {
          strength: { bits: 20, label: 'VERY_WEAK', issues: [] },
          policy_violations: ['Password must contain at least one symbol (for example ! @ # $ %).'], compliant: false,
        },
      }),
    )
    renderPlain(<CredentialFormModal open onClose={vi.fn()} onSaved={vi.fn()} />)
    await userEvent.type(await screen.findByLabelText('Password'), 'longpasswordnosymbol')
    expect(await screen.findByText(/at least one symbol/i, {}, { timeout: 3000 })).toBeInTheDocument()
    expect(api.find('POST', '/api/vault/password/check/').length).toBe(1) // one call after the pause, not one per keystroke
  })

  it('shows server-side field errors next to the fields and keeps the form open', async () => {
    mockApi(
      routes({
        'POST /api/vault/credentials/': fail(400, { password: ['Password must be at least 12 characters long.'], title: ['This field may not be blank.'] }),
      }),
    )
    const onClose = vi.fn()
    renderPlain(<CredentialFormModal open onClose={onClose} onSaved={vi.fn()} />)
    const user = userEvent.setup()
    await user.type(await screen.findByLabelText('Title'), 'x')
    await user.type(screen.getByLabelText('Password'), 'short')
    await user.click(screen.getByRole('button', { name: 'Create credential' }))
    expect(await screen.findByText(/at least 12 characters long/i)).toBeInTheDocument()
    expect(screen.getByText(/may not be blank/i)).toBeInTheDocument()
    expect(onClose).not.toHaveBeenCalled()
  })

  it('a lockdown refusal is explained rather than shown as a generic failure', async () => {
    mockApi(routes({ 'POST /api/vault/credentials/': fail(423, { detail: 'locked', code: 'lockdown_active' }) }))
    renderPlain(<CredentialFormModal open onClose={vi.fn()} onSaved={vi.fn()} />)
    const user = userEvent.setup()
    await user.type(await screen.findByLabelText('Title'), 'Prod DB')
    await user.type(screen.getByLabelText('Password'), PW)
    await user.click(screen.getByRole('button', { name: 'Create credential' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/emergency lockdown/i)
  })
})

describe('CredentialFormModal (edit)', () => {
  const existing = {
    id: 4, title: 'Prod DB', service: 3, service_name: 'AWS', username: 'svc', category: 'DATABASE', tags: ['prod'],
    expiry_date: '2026-12-01',
  } as Credential

  it('leaves the password and unchanged expiry out of the PATCH', async () => {
    const api = mockApi(routes({ 'PATCH /api/vault/credentials/4/': SAVED }))
    const onSaved = vi.fn()
    renderPlain(<CredentialFormModal open credential={existing} onClose={vi.fn()} onSaved={onSaved} />)
    const title = await screen.findByLabelText('Title')
    await userEvent.clear(title)
    await userEvent.type(title, 'Renamed')
    await userEvent.click(screen.getByRole('button', { name: 'Save changes' }))
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
    const body = api.find('PATCH', '/api/vault/credentials/4/')[0].body as Record<string, unknown>
    expect(body).toMatchObject({ title: 'Renamed', service: 3, category: 'DATABASE', tags: ['prod'] })
    expect('password' in body).toBe(false)
    expect('expiry_date' in body).toBe(false)
  })

  it('sends a new password only when one is typed', async () => {
    const api = mockApi(routes({ 'PATCH /api/vault/credentials/4/': SAVED }))
    renderPlain(<CredentialFormModal open credential={existing} onClose={vi.fn()} onSaved={vi.fn()} />)
    expect(await screen.findByText(/leave blank to keep the current password/i)).toBeInTheDocument()
    await userEvent.type(screen.getByLabelText('New password'), PW)
    await userEvent.click(screen.getByRole('button', { name: 'Save changes' }))
    await waitFor(() => expect(api.find('PATCH', '/api/vault/credentials/4/').length).toBe(1))
    expect(api.find('PATCH', '/api/vault/credentials/4/')[0].body).toMatchObject({ password: PW })
  })
})
