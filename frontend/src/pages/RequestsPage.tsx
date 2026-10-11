import { useState, type FormEvent } from 'react'
import { useToast } from '../components/Toast'
import {
  Badge, Button, Checkbox, EmptyState, ErrorBanner, FormError, LoadingBlock, Modal, PageHeader, Pagination, Table, Tabs, Td, Th,
  TextAreaField, TextField, statusTone,
} from '../components/ui'
import { usePageState, useResource } from '../hooks/useResource'
import { api } from '../lib/api'
import { errorMessage, fieldErrors } from '../lib/errors'
import { formatDateTime } from '../lib/format'
import type { AccessRequest, Page } from '../lib/types'

function NewRequestForm({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const { notify } = useToast()
  const [uid, setUid] = useState('')
  const [reason, setReason] = useState('')
  const [hours, setHours] = useState('4')
  const [edit, setEdit] = useState(false)
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [general, setGeneral] = useState<string>()
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setErrors({})
    setGeneral(undefined)
    try {
      await api.post('/vault/access-requests/', {
        credential_uid: uid.trim(),
        reason,
        requested_hours: Number(hours),
        want_edit: edit,
      })
      notify('Request sent. The owner has been notified.')
      onDone()
      onClose()
    } catch (err) {
      const f = fieldErrors(err)
      setErrors(f)
      setGeneral(Object.keys(f).length ? undefined : errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={(e) => void submit(e)} className="space-y-4">
      <FormError message={general} />
      <TextField
        label="Credential ID"
        required
        value={uid}
        onChange={(e) => setUid(e.target.value)}
        error={errors.credential_uid}
        hint="The owner can give you this identifier. It is not guessable."
        placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
      />
      <TextAreaField
        label="Why do you need access?"
        required
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        error={errors.reason}
        hint="At least 10 characters. The approver sees this."
        rows={3}
      />
      <TextField
        label="For how many hours?"
        type="number"
        min={1}
        max={168}
        required
        value={hours}
        onChange={(e) => setHours(e.target.value)}
        error={errors.requested_hours}
        hint="1 to 168 hours (one week)."
      />
      <Checkbox label="I also need to edit it" checked={edit} onChange={(e) => setEdit(e.target.checked)} />
      <div className="flex justify-end gap-2">
        <Button variant="secondary" onClick={onClose}>
          Cancel
        </Button>
        <Button type="submit" loading={busy}>
          Send request
        </Button>
      </div>
    </form>
  )
}

function DecisionForm({ request, approve, onClose, onDone }: { request: AccessRequest; approve: boolean; onClose: () => void; onDone: () => void }) {
  const { notify } = useToast()
  const [note, setNote] = useState('')
  const [hours, setHours] = useState(String(request.requested_hours))
  const [error, setError] = useState<string>()
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(undefined)
    try {
      await api.post(`/vault/access-requests/${request.id}/${approve ? 'approve' : 'reject'}/`, {
        note,
        ...(approve ? { hours: Number(hours) } : {}),
      })
      notify(approve ? 'Request approved.' : 'Request rejected.')
      onDone()
      onClose()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={(e) => void submit(e)} className="space-y-4">
      <FormError message={error} />
      <p className="text-sm text-slate-600 dark:text-slate-300">
        <strong>{request.requester.email}</strong> asks for {request.want_edit ? 'view and edit' : 'view'} access to{' '}
        <strong>{request.credential_title}</strong> for {request.requested_hours}h.
      </p>
      <blockquote className="border-l-4 border-slate-300 pl-3 text-sm italic text-slate-600 dark:text-slate-300">{request.reason}</blockquote>
      {approve && (
        <TextField
          label="Grant access for (hours)"
          type="number"
          min={1}
          max={request.requested_hours}
          value={hours}
          onChange={(e) => setHours(e.target.value)}
          hint={`You can shorten the request (up to ${request.requested_hours}h) but not extend it.`}
        />
      )}
      <TextAreaField label="Note (optional)" rows={2} value={note} onChange={(e) => setNote(e.target.value)} />
      <div className="flex justify-end gap-2">
        <Button variant="secondary" onClick={onClose}>
          Cancel
        </Button>
        <Button type="submit" variant={approve ? 'primary' : 'danger'} loading={busy}>
          {approve ? 'Approve' : 'Reject'}
        </Button>
      </div>
    </form>
  )
}

export function RequestsPage() {
  const { notify } = useToast()
  const [tab, setTab] = useState<'mine' | 'review'>('mine')
  const [page, setPage] = usePageState(tab)
  const [creating, setCreating] = useState(false)
  const [deciding, setDeciding] = useState<{ request: AccessRequest; approve: boolean } | null>(null)
  const list = useResource(() => api.get<Page<AccessRequest>>('/vault/access-requests/', { scope: tab, page }), [tab, page])
  const rows = list.data?.results ?? []

  async function cancel(r: AccessRequest) {
    try {
      await api.post(`/vault/access-requests/${r.id}/cancel/`)
      notify('Request cancelled.')
      list.reload()
    } catch (e) {
      notify(errorMessage(e), 'error')
    }
  }

  return (
    <>
      <PageHeader
        title="Access requests"
        description="Ask for temporary access to a credential, or decide requests for credentials you own."
        actions={<Button onClick={() => setCreating(true)}>Request access</Button>}
      />
      <Tabs
        tabs={[
          { value: 'mine', label: 'My requests' },
          { value: 'review', label: 'To review' },
        ]}
        value={tab}
        onChange={setTab}
      />
      <ErrorBanner error={list.error} onRetry={list.reload} />
      {list.loading && <LoadingBlock />}
      {!list.loading && !list.error && rows.length === 0 && (
        <EmptyState title={tab === 'mine' ? 'You have not requested access to anything' : 'Nothing is waiting for your decision'} />
      )}
      {!list.loading && rows.length > 0 && (
        <>
          <Table caption={tab === 'mine' ? 'Your access requests' : 'Requests awaiting review'}>
            <thead>
              <tr>
                <Th>Credential</Th>
                <Th>{tab === 'mine' ? 'Decided by' : 'Requester'}</Th>
                <Th>Request</Th>
                <Th>Status</Th>
                <Th />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {rows.map((r) => (
                <tr key={r.id}>
                  <Td>{r.credential_title}</Td>
                  <Td>{tab === 'mine' ? (r.decided_by?.email ?? '—') : r.requester.email}</Td>
                  <Td className="max-w-xs whitespace-normal">
                    <span className="block">
                      {r.requested_hours}h{r.want_edit ? ' · edit' : ''} · {formatDateTime(r.created_at)}
                    </span>
                    <span className="block text-xs text-slate-500">{r.reason}</span>
                    {r.decision_note && <span className="block text-xs italic text-slate-500">Note: {r.decision_note}</span>}
                  </Td>
                  <Td>
                    <Badge tone={statusTone(r.status)}>{r.status}</Badge>
                  </Td>
                  <Td>
                    {r.can_decide && (
                      <span className="flex gap-1">
                        <Button variant="secondary" onClick={() => setDeciding({ request: r, approve: true })} aria-label={`Approve request from ${r.requester.email}`}>
                          Approve
                        </Button>
                        <Button variant="ghost" onClick={() => setDeciding({ request: r, approve: false })} aria-label={`Reject request from ${r.requester.email}`}>
                          Reject
                        </Button>
                      </span>
                    )}
                    {tab === 'mine' && r.status === 'PENDING' && (
                      <Button variant="ghost" onClick={() => void cancel(r)} aria-label={`Cancel request for ${r.credential_title}`}>
                        Cancel
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

      <Modal open={creating} onClose={() => setCreating(false)} title="Request access">
        <NewRequestForm onClose={() => setCreating(false)} onDone={list.reload} />
      </Modal>
      <Modal open={!!deciding} onClose={() => setDeciding(null)} title={deciding?.approve ? 'Approve request' : 'Reject request'}>
        {deciding && <DecisionForm request={deciding.request} approve={deciding.approve} onClose={() => setDeciding(null)} onDone={list.reload} />}
      </Modal>
    </>
  )
}
