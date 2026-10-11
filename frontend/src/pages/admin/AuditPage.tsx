import { useState } from 'react'
import { Badge, EmptyState, ErrorBanner, LoadingBlock, PageHeader, Pagination, SelectField, Table, Td, Th, statusTone } from '../../components/ui'
import { usePageState, useResource } from '../../hooks/useResource'
import { api } from '../../lib/api'
import { formatDateTime } from '../../lib/format'
import type { AuditEventRow, Page } from '../../lib/types'

const ACTIONS = [
  'LOGIN', 'LOGOUT', 'REVEAL', 'CREATE', 'EDIT', 'SHARE', 'REVOKE', 'ACCESS_REQUEST', 'ACCESS_DECISION', 'POLICY_CHANGE',
  'ACCOUNT_STATUS_CHANGE', 'AUTHZ_DENIED',
]

export function AuditPage() {
  const [action, setAction] = useState('')
  const [outcome, setOutcome] = useState('')
  const [page, setPage] = usePageState(JSON.stringify([action, outcome]))
  const list = useResource(() => api.get<Page<AuditEventRow>>('/audit/events/', { action, outcome, page }), [action, outcome, page])
  const rows = list.data?.results ?? []
  return (
    <>
      <PageHeader
        title="Audit log"
        description="An append-only, tamper-evident record. It never contains passwords, notes or keys."
      />
      <div className="mb-4 grid gap-3 sm:grid-cols-3">
        <SelectField label="Action" value={action} onChange={(e) => setAction(e.target.value)}>
          <option value="">All actions</option>
          {ACTIONS.map((a) => (
            <option key={a} value={a}>{a.replace(/_/g, ' ').toLowerCase()}</option>
          ))}
        </SelectField>
        <SelectField label="Outcome" value={outcome} onChange={(e) => setOutcome(e.target.value)}>
          <option value="">All outcomes</option>
          <option value="SUCCESS">Success</option>
          <option value="DENIED">Denied</option>
          <option value="FAILURE">Failure</option>
        </SelectField>
      </div>
      <ErrorBanner error={list.error} onRetry={list.reload} />
      {list.loading && <LoadingBlock />}
      {!list.loading && !list.error && rows.length === 0 && <EmptyState title="No events match" />}
      {rows.length > 0 && (
        <>
          <Table caption="Audit events, newest first">
            <thead>
              <tr><Th>When</Th><Th>Actor</Th><Th>Action</Th><Th>Target</Th><Th>Outcome</Th><Th>Detail</Th><Th>IP</Th></tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {rows.map((e) => (
                <tr key={e.id}>
                  <Td>{formatDateTime(e.created_at)}</Td>
                  <Td>{e.actor_email || '—'}</Td>
                  <Td>{e.action}</Td>
                  <Td>{e.target_type ? `${e.target_type} #${e.target_id}` : '—'}</Td>
                  <Td><Badge tone={statusTone(e.outcome)}>{e.outcome}</Badge></Td>
                  <Td>{e.reason_code || '—'}</Td>
                  <Td>{e.ip_address ?? '—'}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
          <Pagination page={page} count={list.data?.count ?? 0} onPage={setPage} />
        </>
      )}
    </>
  )
}
