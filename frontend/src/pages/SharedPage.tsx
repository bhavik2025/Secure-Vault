import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useToast } from '../components/Toast'
import { Badge, Button, ConfirmDialog, EmptyState, ErrorBanner, LoadingBlock, PageHeader, Pagination, Table, Tabs, Td, Th, statusTone } from '../components/ui'
import { usePageState, useResource } from '../hooks/useResource'
import { api } from '../lib/api'
import { errorMessage } from '../lib/errors'
import { formatDateTime, relativeTime } from '../lib/format'
import type { Page, Share } from '../lib/types'

function Perms({ s }: { s: Share }) {
  return (
    <span className="flex flex-wrap gap-1">
      {s.can_view && <Badge tone="info">View</Badge>}
      {s.can_edit && <Badge tone="warn">Edit</Badge>}
      {s.can_share && <Badge>Share</Badge>}
      {s.is_view_once && <Badge tone="warn">One-time</Badge>}
    </span>
  )
}

export function SharedPage() {
  const { notify } = useToast()
  const [tab, setTab] = useState<'with' | 'by'>('with')
  const [page, setPage] = usePageState(tab)
  const [revoking, setRevoking] = useState<Share | null>(null)
  const [busy, setBusy] = useState(false)
  const path = tab === 'with' ? '/vault/shared-with-me/' : '/vault/shared-by-me/'
  const list = useResource(() => api.get<Page<Share>>(path, { page }), [path, page])
  const rows = list.data?.results ?? []

  async function revoke() {
    if (!revoking) return
    setBusy(true)
    try {
      await api.post(`/vault/shares/${revoking.id}/revoke/`)
      notify('Access revoked.')
      setRevoking(null)
      list.reload()
    } catch (e) {
      notify(errorMessage(e), 'error')
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <PageHeader title="Shared" description="Credentials shared with you, and access you have given to others." />
      <Tabs
        tabs={[
          { value: 'with', label: 'Shared with me' },
          { value: 'by', label: 'Shared by me' },
        ]}
        value={tab}
        onChange={setTab}
      />
      <ErrorBanner error={list.error} onRetry={list.reload} />
      {list.loading && <LoadingBlock />}
      {!list.loading && !list.error && rows.length === 0 && (
        <EmptyState title={tab === 'with' ? 'Nothing has been shared with you' : 'You have not shared anything'}>
          {tab === 'with' ? 'You can ask a colleague for access from the Access requests page.' : 'Open a credential in your vault and choose Share.'}
        </EmptyState>
      )}
      {!list.loading && rows.length > 0 && (
        <>
          <Table caption={tab === 'with' ? 'Credentials shared with you' : 'Access you have granted'}>
            <thead>
              <tr>
                <Th>Credential</Th>
                <Th>{tab === 'with' ? 'Shared by' : 'Shared with'}</Th>
                <Th>Permissions</Th>
                <Th>Expires</Th>
                <Th>Status</Th>
                <Th />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {rows.map((s) => (
                <tr key={s.id}>
                  <Td>
                    {s.status === 'ACTIVE' && tab === 'with' ? (
                      <Link to={`/vault/${s.credential}`} className="font-medium text-indigo-600 hover:underline">
                        {s.credential_title}
                      </Link>
                    ) : (
                      s.credential_title
                    )}
                  </Td>
                  <Td>{tab === 'with' ? s.grantor.email : s.grantee.email}</Td>
                  <Td>
                    <Perms s={s} />
                  </Td>
                  <Td>
                    {s.expires_at ? (
                      <>
                        {formatDateTime(s.expires_at)} <span className="text-xs text-slate-500">({relativeTime(s.expires_at)})</span>
                      </>
                    ) : (
                      'Never'
                    )}
                  </Td>
                  <Td>
                    <Badge tone={statusTone(s.status)}>{s.status}</Badge>
                  </Td>
                  <Td>
                    {tab === 'by' && s.status === 'ACTIVE' && (
                      <Button variant="ghost" onClick={() => setRevoking(s)} aria-label={`Revoke ${s.grantee.email} on ${s.credential_title}`}>
                        Revoke
                      </Button>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
          <Pagination page={page} count={list.data?.count ?? 0} onPage={setPage} />
        </>
      )}
      <ConfirmDialog
        open={!!revoking}
        danger
        busy={busy}
        title="Revoke access?"
        confirmLabel="Revoke"
        message={`${revoking?.grantee.email} will lose access immediately, along with anyone they passed it on to.`}
        onConfirm={() => void revoke()}
        onCancel={() => setRevoking(null)}
      />
    </>
  )
}
