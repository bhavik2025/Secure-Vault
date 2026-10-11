import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import type { AppNotification } from '../lib/types'
import { mockApi, page, renderPlain } from '../test/utils'
import { NotificationsPage } from './NotificationsPage'

afterEach(() => vi.restoreAllMocks())

const note = (over: Partial<AppNotification> = {}): AppNotification => ({
  id: 1, type: 'SHARE_RECEIVED', title: 'A credential was shared with you', message: "Ada shared 'Prod DB' with you.", priority: 'NORMAL',
  is_read: false, related_type: 'credential', related_id: '1', created_at: '2026-01-01T10:00:00Z', ...over,
})

it('marks one notification read and refreshes the shell badge', async () => {
  const api = mockApi({
    'GET /api/notifications/': page([note(), note({ id: 2, title: 'Old news', is_read: true })]),
    'POST /api/notifications/1/read/': note({ is_read: true }),
  })
  const changed = vi.fn()
  window.addEventListener('sv:notifications-changed', changed)
  renderPlain(<NotificationsPage />)
  expect(await screen.findByText('A credential was shared with you')).toBeInTheDocument()
  expect(screen.getAllByText('New')).toHaveLength(1)
  await userEvent.click(screen.getByRole('button', { name: /mark "a credential was shared with you" as read/i }))
  await waitFor(() => expect(api.find('POST', '/api/notifications/1/read/')).toHaveLength(1))
  expect(changed).toHaveBeenCalled()
  window.removeEventListener('sv:notifications-changed', changed)
})

it('flags high priority items and supports mark-all and the unread filter', async () => {
  const api = mockApi({
    'GET /api/notifications/': page([note({ priority: 'HIGH' })]),
    'POST /api/notifications/read-all/': { updated: 1 },
  })
  renderPlain(<NotificationsPage />)
  expect(await screen.findByText('High')).toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Mark all read' }))
  await waitFor(() => expect(api.find('POST', '/api/notifications/read-all/')).toHaveLength(1))
  await userEvent.click(screen.getByRole('button', { name: /show unread only/i }))
  await waitFor(() => expect(api.find('GET', '/api/notifications/').at(-1)!.query).toMatchObject({ unread: 'true' }))
})

it('has an empty state', async () => {
  mockApi({ 'GET /api/notifications/': page([]) })
  renderPlain(<NotificationsPage />)
  expect(await screen.findByText('No notifications yet')).toBeInTheDocument()
})

it('renders message text as text, never as HTML', async () => {
  mockApi({ 'GET /api/notifications/': page([note({ message: '<img src=x onerror=alert(1)>' })]) })
  renderPlain(<NotificationsPage />)
  const el = await screen.findByText('<img src=x onerror=alert(1)>')
  expect(el.querySelector('img')).toBeNull()
})
