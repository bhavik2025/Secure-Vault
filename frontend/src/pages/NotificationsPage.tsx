import { useState } from 'react'
import { NOTIFICATIONS_CHANGED } from '../components/Layout'
import { Badge, Button, EmptyState, ErrorBanner, LoadingBlock, PageHeader, Pagination } from '../components/ui'
import { useResource } from '../hooks/useResource'
import { api } from '../lib/api'
import { formatDateTime } from '../lib/format'
import type { AppNotification, Page } from '../lib/types'

export function NotificationsPage() {
  const [page, setPage] = useState(1)
  const [unreadOnly, setUnreadOnly] = useState(false)
  const list = useResource(
    () => api.get<Page<AppNotification>>('/notifications/', { page, unread: unreadOnly ? 'true' : undefined }),
    [page, unreadOnly],
  )
  const rows = list.data?.results ?? []

  async function markRead(n: AppNotification) {
    if (n.is_read) return
    await api.post(`/notifications/${n.id}/read/`).catch(() => undefined)
    window.dispatchEvent(new Event(NOTIFICATIONS_CHANGED))
    list.reload()
  }
  async function markAll() {
    await api.post('/notifications/read-all/').catch(() => undefined)
    window.dispatchEvent(new Event(NOTIFICATIONS_CHANGED))
    list.reload()
  }

  return (
    <>
      <PageHeader
        title="Notifications"
        actions={
          <>
            <Button variant="secondary" aria-pressed={unreadOnly} onClick={() => { setUnreadOnly((u) => !u); setPage(1) }}>
              {unreadOnly ? 'Showing unread' : 'Show unread only'}
            </Button>
            <Button variant="secondary" onClick={() => void markAll()}>
              Mark all read
            </Button>
          </>
        }
      />
      <ErrorBanner error={list.error} onRetry={list.reload} />
      {list.loading && <LoadingBlock />}
      {!list.loading && !list.error && rows.length === 0 && <EmptyState title={unreadOnly ? 'No unread notifications' : 'No notifications yet'} />}
      <ul className="space-y-3">
        {rows.map((n) => (
          <li
            key={n.id}
            className={`rounded-xl p-4 ring-1 ${n.is_read ? 'bg-white ring-slate-200 dark:bg-slate-900 dark:ring-slate-800' : 'bg-indigo-50 ring-indigo-200 dark:bg-indigo-950 dark:ring-indigo-900'}`}
          >
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="flex items-center gap-2 font-medium text-slate-900 dark:text-slate-100">
                  {n.title}
                  {n.priority === 'HIGH' && <Badge tone="bad">High</Badge>}
                  {!n.is_read && <Badge tone="info">New</Badge>}
                </p>
                <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">{n.message}</p>
                <p className="mt-1 text-xs text-slate-400">{formatDateTime(n.created_at)}</p>
              </div>
              {!n.is_read && (
                <Button variant="ghost" onClick={() => void markRead(n)} aria-label={`Mark "${n.title}" as read`}>
                  Mark read
                </Button>
              )}
            </div>
          </li>
        ))}
      </ul>
      <Pagination page={page} count={list.data?.count ?? 0} onPage={setPage} />
    </>
  )
}
