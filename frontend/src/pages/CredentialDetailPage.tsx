import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { CredentialFormModal } from '../components/CredentialFormModal'
import { SecretReveal } from '../components/SecretReveal'
import { SharesPanel } from '../components/SharesPanel'
import { StrengthMeter } from '../components/StrengthMeter'
import { useToast } from '../components/Toast'
import { Badge, Button, Card, ConfirmDialog, ErrorBanner, LoadingBlock, PageHeader, statusTone } from '../components/ui'
import { useResource } from '../hooks/useResource'
import { api } from '../lib/api'
import { errorMessage } from '../lib/errors'
import { CATEGORY_LABELS, formatDate, formatDateTime, relativeTime, WARNING_LABELS } from '../lib/format'
import type { Credential } from '../lib/types'

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-3 gap-3 py-2 text-sm">
      <dt className="text-slate-500">{label}</dt>
      <dd className="col-span-2 text-slate-900 dark:text-slate-100">{children}</dd>
    </div>
  )
}

export function CredentialDetailPage() {
  const { id } = useParams()
  const { notify } = useToast()
  const res = useResource(() => api.get<Credential>(`/vault/credentials/${id}/`), [id])
  const [editing, setEditing] = useState(false)
  const [archiving, setArchiving] = useState(false)
  const [busy, setBusy] = useState(false)

  if (res.loading && !res.data) return <LoadingBlock label="Loading credential…" />
  if (res.error || !res.data) {
    return (
      <>
        <PageHeader title="Credential" />
        <ErrorBanner error={res.error} onRetry={res.reload} />
        <p className="mt-4 text-sm">
          <Link to="/vault" className="text-indigo-600 hover:underline">
            Back to your vault
          </Link>
        </p>
      </>
    )
  }

  const c = res.data
  const isOwner = c.access.role === 'owner'
  const archived = c.status === 'ARCHIVED'

  async function copyRequestCode(code: string) {
    try {
      await navigator.clipboard.writeText(code)
      notify('Access request ID copied.', 'info')
    } catch {
      notify('Could not copy. Your browser blocked clipboard access.', 'error')
    }
  }

  async function setArchived(next: boolean) {
    setBusy(true)
    try {
      await api.post(`/vault/credentials/${c.id}/${next ? 'archive' : 'unarchive'}/`)
      notify(next ? 'Credential archived.' : 'Credential restored.')
      setArchiving(false)
      res.reload()
    } catch (e) {
      notify(errorMessage(e), 'error')
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <p className="mb-2 text-sm">
        <Link to="/vault" className="text-indigo-600 hover:underline">
          ← Vault
        </Link>
      </p>
      <PageHeader
        title={c.title}
        description={isOwner ? 'You own this credential.' : `Shared with you by ${c.owner.full_name || c.owner.email}.`}
        actions={
          <>
            {c.access.can_edit && !archived && (
              <Button variant="secondary" onClick={() => setEditing(true)}>
                Edit
              </Button>
            )}
            {isOwner && (
              <Button variant="secondary" onClick={() => (archived ? void setArchived(false) : setArchiving(true))} loading={busy && archived}>
                {archived ? 'Restore' : 'Archive'}
              </Button>
            )}
          </>
        }
      />

      <div className="mb-4 flex flex-wrap gap-2">
        <Badge tone={statusTone(c.status)}>{c.status}</Badge>
        {!isOwner && <Badge tone="info">Shared with you</Badge>}
        {c.access.view_once && <Badge tone="warn">One-time view</Badge>}
        {c.warnings.map((w) => (
          <Badge key={w} tone="warn">
            {WARNING_LABELS[w] ?? w}
          </Badge>
        ))}
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Details">
          <dl className="divide-y divide-slate-100 dark:divide-slate-800">
            <Row label="Service">{c.service_name ?? '—'}</Row>
            <Row label="Username">{c.username || '—'}</Row>
            <Row label="Category">{CATEGORY_LABELS[c.category] ?? c.category}</Row>
            <Row label="Tags">{c.tags.length ? c.tags.map((t) => `#${t}`).join(' ') : '—'}</Row>
            <Row label="Expires">
              {formatDate(c.expiry_date)} {c.expiry_date && <span className="text-slate-500">({relativeTime(`${c.expiry_date}T00:00:00`)})</span>}
            </Row>
            <Row label="Password changed">{formatDateTime(c.password_changed_at)}</Row>
            <Row label="Owner">{c.owner.email}</Row>
            {!isOwner && c.access.expires_at && <Row label="Your access ends">{formatDateTime(c.access.expires_at)}</Row>}
            {c.request_code && (
              <Row label="Access request ID">
                <span className="flex flex-wrap items-center gap-2">
                  <code className="break-all rounded bg-slate-100 px-1.5 py-0.5 text-xs dark:bg-slate-800">{c.request_code}</code>
                  <Button variant="ghost" onClick={() => void copyRequestCode(c.request_code!)} aria-label="Copy access request ID">
                    Copy
                  </Button>
                </span>
                <span className="mt-1 block text-xs text-slate-500">Give this to a colleague so they can request access. It is not a secret.</span>
              </Row>
            )}
          </dl>
        </Card>

        <Card title="Secret">
          {c.access.can_view && !archived ? (
            <SecretReveal
              endpoint={`/vault/credentials/${c.id}/reveal/`}
              field="password"
              label="Password"
              viewOnce={c.access.view_once}
            />
          ) : archived ? (
            <p className="text-sm text-slate-500">Restore this credential to reveal its secret.</p>
          ) : (
            <p className="text-sm text-slate-500">You can edit this credential but were not given permission to view the secret.</p>
          )}
          <div className="mt-5 border-t border-slate-100 pt-4 dark:border-slate-800">
            <StrengthMeter strength={c.strength} />
          </div>
        </Card>
      </div>

      {(isOwner || c.access.can_share) && !archived && (
        <div className="mt-6">
          <SharesPanel credentialId={c.id} access={c.access} />
        </div>
      )}

      <CredentialFormModal open={editing} onClose={() => setEditing(false)} onSaved={() => res.reload()} credential={c} />
      <ConfirmDialog
        open={archiving}
        busy={busy}
        title="Archive this credential?"
        confirmLabel="Archive"
        message="It will be hidden from your vault and its secret can no longer be revealed. Existing shares are kept but stop working until you restore it."
        onConfirm={() => void setArchived(true)}
        onCancel={() => setArchiving(false)}
      />
    </>
  )
}
