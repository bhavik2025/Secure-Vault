import { useState, type FormEvent } from 'react'
import { useAuth } from '../../auth/AuthContext'
import { useToast } from '../../components/Toast'
import {
  Badge, Button, EmptyState, ErrorBanner, FormError, LoadingBlock, Modal, PageHeader, Pagination, SelectField, Table, Td, Th,
  TextField, statusTone,
} from '../../components/ui'
import { useResource } from '../../hooks/useResource'
import { api } from '../../lib/api'
import { errorMessage } from '../../lib/errors'
import { formatDateTime, ROLE_LABELS } from '../../lib/format'
import type { Employee, Page } from '../../lib/types'

const TRANSITIONS: Record<Employee['status'], { value: Employee['status']; label: string }[]> = {
  ACTIVE: [{ value: 'SUSPENDED', label: 'Suspend' }, { value: 'DEACTIVATED', label: 'Deactivate' }],
  SUSPENDED: [{ value: 'ACTIVE', label: 'Reactivate' }, { value: 'DEACTIVATED', label: 'Deactivate' }],
  INVITED: [{ value: 'DEACTIVATED', label: 'Deactivate' }],
  DEACTIVATED: [],
}

function StatusForm({ employee, onClose, onDone }: { employee: Employee; onClose: () => void; onDone: () => void }) {
  const { notify } = useToast()
  const options = TRANSITIONS[employee.status]
  const [status, setStatus] = useState(options[0]?.value ?? '')
  const [reason, setReason] = useState('')
  const [error, setError] = useState<string>()
  const [busy, setBusy] = useState(false)
  const destructive = status === 'SUSPENDED' || status === 'DEACTIVATED'

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(undefined)
    try {
      await api.post(`/org/employees/${employee.id}/status/`, { status, reason })
      notify(`${employee.email} is now ${status.toLowerCase()}.`)
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
        Changing the status of <strong>{employee.email}</strong>.
        {destructive && ' Their active sessions end immediately.'} Deactivation cannot be undone.
      </p>
      <SelectField label="New status" value={status} onChange={(e) => setStatus(e.target.value as Employee['status'])}>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </SelectField>
      <TextField label="Reason" required minLength={3} maxLength={300} value={reason} onChange={(e) => setReason(e.target.value)} hint="Recorded in the audit log." />
      <div className="flex justify-end gap-2">
        <Button variant="secondary" onClick={onClose}>Cancel</Button>
        <Button type="submit" variant={destructive ? 'danger' : 'primary'} loading={busy}>Confirm</Button>
      </div>
    </form>
  )
}

export function EmployeesPage() {
  const { can, user } = useAuth()
  const manage = can('users.manage')
  const [page, setPage] = useState(1)
  const [target, setTarget] = useState<Employee | null>(null)
  const list = useResource(() => api.get<Page<Employee>>('/org/employees/', { page }), [page])
  const rows = list.data?.results ?? []
  return (
    <>
      <PageHeader title="Employees" description="Account status and roles. Account creation and bulk import arrive with the onboarding module." />
      <ErrorBanner error={list.error} onRetry={list.reload} />
      {list.loading && <LoadingBlock />}
      {!list.loading && !list.error && rows.length === 0 && <EmptyState title="No employees" />}
      {rows.length > 0 && (
        <>
          <Table caption="Employees">
            <thead>
              <tr><Th>Name</Th><Th>Email</Th><Th>Roles</Th><Th>Status</Th><Th>Last sign-in</Th><Th /></tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {rows.map((e) => (
                <tr key={e.id}>
                  <Td>{e.full_name || '—'}</Td>
                  <Td>{e.email}</Td>
                  <Td>{e.roles.map((r) => ROLE_LABELS[r] ?? r).join(', ') || '—'}</Td>
                  <Td><Badge tone={statusTone(e.status)}>{e.status}</Badge></Td>
                  <Td>{formatDateTime(e.last_login)}</Td>
                  <Td>
                    {manage && e.id !== user?.id && TRANSITIONS[e.status].length > 0 && (
                      <Button variant="ghost" onClick={() => setTarget(e)} aria-label={`Change status of ${e.email}`}>
                        Change status
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
      <Modal open={!!target} onClose={() => setTarget(null)} title="Change account status">
        {target && <StatusForm employee={target} onClose={() => setTarget(null)} onDone={list.reload} />}
      </Modal>
    </>
  )
}
