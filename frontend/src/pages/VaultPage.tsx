import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { CredentialFormModal } from '../components/CredentialFormModal'
import { Badge, Button, EmptyState, ErrorBanner, LoadingBlock, PageHeader, Pagination, SelectField, Table, Td, Th, TextField, statusTone } from '../components/ui'
import { useDebounced, usePageState, useResource } from '../hooks/useResource'
import { api } from '../lib/api'
import { formatDate, WARNING_LABELS } from '../lib/format'
import { CATEGORIES, type Credential, type Page } from '../lib/types'

export function VaultPage() {
  const navigate = useNavigate()
  const [q, setQ] = useState('')
  const [category, setCategory] = useState('')
  const [status, setStatus] = useState<'ACTIVE' | 'ARCHIVED'>('ACTIVE')
  const [expiry, setExpiry] = useState('')
  const [ordering, setOrdering] = useState('title')
  const [creating, setCreating] = useState(false)
  const dq = useDebounced(q)
  const [page, setPage] = usePageState(JSON.stringify([dq, category, status, expiry, ordering]))
  const list = useResource(
    () => api.get<Page<Credential>>('/vault/credentials/', { q: dq, category, status, expiry, ordering, page }),
    [dq, category, status, expiry, ordering, page],
  )
  const rows = list.data?.results ?? []

  return (
    <>
      <PageHeader
        title="Vault"
        description="Your credentials. Secrets stay masked until you reveal them."
        actions={<Button onClick={() => setCreating(true)}>New credential</Button>}
      />

      <form role="search" aria-label="Filter credentials" className="mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-5" onSubmit={(e) => e.preventDefault()}>
        <TextField label="Search" type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Title, username or service" />
        <SelectField label="Category" value={category} onChange={(e) => setCategory(e.target.value)}>
          <option value="">All categories</option>
          {CATEGORIES.map((c) => (
            <option key={c.value} value={c.value}>
              {c.label}
            </option>
          ))}
        </SelectField>
        <SelectField label="Expiry" value={expiry} onChange={(e) => setExpiry(e.target.value)}>
          <option value="">Any</option>
          <option value="soon">Expiring within 14 days</option>
          <option value="expired">Expired</option>
        </SelectField>
        <SelectField label="Show" value={status} onChange={(e) => setStatus(e.target.value as 'ACTIVE' | 'ARCHIVED')}>
          <option value="ACTIVE">Active</option>
          <option value="ARCHIVED">Archived</option>
        </SelectField>
        <SelectField label="Sort by" value={ordering} onChange={(e) => setOrdering(e.target.value)}>
          <option value="title">Title (A-Z)</option>
          <option value="-updated_at">Recently updated</option>
          <option value="expiry_date">Expiry (soonest)</option>
          <option value="-created_at">Newest</option>
        </SelectField>
      </form>

      <ErrorBanner error={list.error} onRetry={list.reload} />
      {list.loading && <LoadingBlock label="Loading credentials…" />}
      {!list.loading && !list.error && rows.length === 0 && (
        <EmptyState title={q || category || expiry ? 'No credentials match your filters' : status === 'ARCHIVED' ? 'No archived credentials' : 'Your vault is empty'}>
          {!q && !category && !expiry && status === 'ACTIVE' && 'Create your first credential to get started.'}
        </EmptyState>
      )}
      {!list.loading && rows.length > 0 && (
        <>
          <Table caption="Your credentials">
            <thead>
              <tr>
                <Th>Title</Th>
                <Th>Service</Th>
                <Th>Username</Th>
                <Th>Expires</Th>
                <Th>Health</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {rows.map((c) => (
                <tr key={c.id} className="hover:bg-slate-50 dark:hover:bg-slate-900">
                  <Td>
                    <Link to={`/vault/${c.id}`} className="font-medium text-indigo-600 hover:underline">
                      {c.title}
                    </Link>
                    {c.tags.length > 0 && <span className="ml-2 text-xs text-slate-400">{c.tags.map((t) => `#${t}`).join(' ')}</span>}
                  </Td>
                  <Td>{c.service_name ?? '—'}</Td>
                  <Td>{c.username || '—'}</Td>
                  <Td>{formatDate(c.expiry_date)}</Td>
                  <Td>
                    <span className="flex flex-wrap gap-1">
                      {c.warnings.length === 0 && <Badge tone="good">Healthy</Badge>}
                      {c.warnings.map((w) => (
                        <Badge key={w} tone={statusTone(w) === 'neutral' ? 'warn' : statusTone(w)}>
                          {WARNING_LABELS[w] ?? w}
                        </Badge>
                      ))}
                    </span>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
          <Pagination page={page} count={list.data?.count ?? 0} onPage={setPage} />
        </>
      )}

      <CredentialFormModal open={creating} onClose={() => setCreating(false)} onSaved={(c) => navigate(`/vault/${c.id}`)} />
    </>
  )
}
