import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import type { AccessRequest } from '../lib/types'
import { fail, mockApi, page, renderPlain } from '../test/utils'
import { RequestsPage } from './RequestsPage'

afterEach(() => vi.restoreAllMocks())

const req = (over: Partial<AccessRequest> = {}): AccessRequest => ({
  id: 5, credential_uid: 'aaaaaaaa-0000-0000-0000-000000000001', credential_title: 'Prod DB',
  requester: { id: 2, email: 'bob@acme.example', full_name: 'Bob' }, reason: 'Rotate the production credentials',
  requested_hours: 4, want_edit: false, status: 'PENDING', decided_by: null, decided_at: null, decision_note: '',
  resulting_share: null, can_decide: false, created_at: '2026-01-01T10:00:00Z', ...over,
})

it('lists my requests and lets me cancel a pending one', async () => {
  const api = mockApi({
    'GET /api/vault/access-requests/': page([req(), req({ id: 6, status: 'APPROVED', credential_title: 'Other' })]),
    'POST /api/vault/access-requests/5/cancel/': req({ status: 'CANCELLED' }),
  })
  renderPlain(<RequestsPage />)
  expect(await screen.findByText('Prod DB')).toBeInTheDocument()
  expect(api.calls[0].query).toMatchObject({ scope: 'mine' })
  expect(screen.getAllByRole('button', { name: /cancel request/i })).toHaveLength(1) // only the pending one
  await userEvent.click(screen.getByRole('button', { name: /cancel request for prod db/i }))
  await waitFor(() => expect(api.find('POST', '/api/vault/access-requests/5/cancel/')).toHaveLength(1))
})

it('files a new request with the right payload and explains server rejections', async () => {
  const api = mockApi({
    'GET /api/vault/access-requests/': page([]),
    'POST /api/vault/access-requests/': fail(409, { detail: 'x', code: 'conflict' }),
  })
  renderPlain(<RequestsPage />)
  await userEvent.click(await screen.findByRole('button', { name: 'Request access' }))
  const user = userEvent.setup()
  await user.type(screen.getByLabelText('Credential ID'), 'aaaaaaaa-0000-0000-0000-000000000001')
  await user.type(screen.getByLabelText(/why do you need access/i), 'Rotate the production credentials')
  await user.clear(screen.getByLabelText(/how many hours/i))
  await user.type(screen.getByLabelText(/how many hours/i), '8')
  await user.click(screen.getByLabelText(/also need to edit/i))
  await user.click(screen.getByRole('button', { name: 'Send request' }))
  await waitFor(() => expect(api.find('POST', '/api/vault/access-requests/')).toHaveLength(1))
  expect(api.find('POST', '/api/vault/access-requests/')[0].body).toEqual({
    credential_uid: 'aaaaaaaa-0000-0000-0000-000000000001', reason: 'Rotate the production credentials', requested_hours: 8, want_edit: true,
  })
  expect(await screen.findByRole('alert')).toBeInTheDocument()
})

it('an approver reviews requests, can shorten the lease, and approval is sent with the chosen hours', async () => {
  const api = mockApi({
    'GET /api/vault/access-requests/': page([req({ can_decide: true })]),
    'POST /api/vault/access-requests/5/approve/': req({ status: 'APPROVED' }),
  })
  renderPlain(<RequestsPage />)
  await userEvent.click(await screen.findByRole('tab', { name: 'To review' }))
  await userEvent.click(await screen.findByRole('button', { name: /approve request from bob@acme.example/i }))
  const dialog = await screen.findByRole('dialog')
  expect(within(dialog).getByText(/rotate the production credentials/i)).toBeInTheDocument()
  const hours = within(dialog).getByLabelText(/grant access for/i)
  expect(hours).toHaveAttribute('max', '4') // cannot extend beyond what was asked
  await userEvent.clear(hours)
  await userEvent.type(hours, '2')
  await userEvent.type(within(dialog).getByLabelText(/note/i), 'ok')
  await userEvent.click(within(dialog).getByRole('button', { name: 'Approve' }))
  await waitFor(() => expect(api.find('POST', '/api/vault/access-requests/5/approve/')).toHaveLength(1))
  expect(api.find('POST', '/api/vault/access-requests/5/approve/')[0].body).toEqual({ note: 'ok', hours: 2 })
  expect(api.calls.find((c) => c.query.scope === 'review')).toBeDefined()
})

it('rejecting sends no duration', async () => {
  const api = mockApi({
    'GET /api/vault/access-requests/': page([req({ can_decide: true })]),
    'POST /api/vault/access-requests/5/reject/': req({ status: 'REJECTED' }),
  })
  renderPlain(<RequestsPage />)
  await userEvent.click(await screen.findByRole('tab', { name: 'To review' }))
  await userEvent.click(await screen.findByRole('button', { name: /reject request from bob/i }))
  await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Reject' }))
  await waitFor(() => expect(api.find('POST', '/api/vault/access-requests/5/reject/')).toHaveLength(1))
  expect(api.find('POST', '/api/vault/access-requests/5/reject/')[0].body).toEqual({ note: '' })
})

it('shows an empty state per tab', async () => {
  mockApi({ 'GET /api/vault/access-requests/': page([]) })
  renderPlain(<RequestsPage />)
  expect(await screen.findByText(/have not requested access/i)).toBeInTheDocument()
  await userEvent.click(screen.getByRole('tab', { name: 'To review' }))
  expect(await screen.findByText(/waiting for your decision/i)).toBeInTheDocument()
})
