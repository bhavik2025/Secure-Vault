import { useState, type FormEvent } from 'react'
import { useAuth } from '../../auth/AuthContext'
import { useToast } from '../../components/Toast'
import {
  Badge, Button, EmptyState, ErrorBanner, FormError, LoadingBlock, Modal, PageHeader, Pagination, SelectField, Table, Td, Th,
  TextField, statusTone,
} from '../../components/ui'
import { useResource } from '../../hooks/useResource'
import { api } from '../../lib/api'
import { errorMessage, fieldErrors } from '../../lib/errors'
import type { Department, Employee, Page } from '../../lib/types'

function DepartmentForm({ dept, onClose, onSaved }: { dept?: Department; onClose: () => void; onSaved: () => void }) {
  const { can } = useAuth()
  const { notify } = useToast()
  const people = useResource(() => (can('users.view') ? api.get<Page<Employee>>('/org/employees/') : Promise.resolve(null)), [])
  const [name, setName] = useState(dept?.name ?? '')
  const [code, setCode] = useState(dept?.code ?? '')
  const [head, setHead] = useState(dept?.head ? String(dept.head) : '')
  const [status, setStatus] = useState<Department['status']>(dept?.status ?? 'ACTIVE')
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [general, setGeneral] = useState<string>()
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setErrors({})
    setGeneral(undefined)
    const body = { name, code, head: head ? Number(head) : null, status }
    try {
      if (dept) await api.patch(`/org/departments/${dept.id}/`, body)
      else await api.post('/org/departments/', body)
      notify(dept ? 'Department updated.' : 'Department created.')
      onSaved()
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
      <TextField label="Name" required value={name} onChange={(e) => setName(e.target.value)} error={errors.name} />
      <TextField label="Code" required maxLength={20} value={code} onChange={(e) => setCode(e.target.value.toUpperCase())} error={errors.code} hint="Short unique code, e.g. ENG" />
      <SelectField label="Department head" value={head} onChange={(e) => setHead(e.target.value)} error={errors.head}>
        <option value="">No head</option>
        {people.data?.results.map((p) => (
          <option key={p.id} value={p.id}>
            {p.full_name || p.email}
          </option>
        ))}
      </SelectField>
      <SelectField label="Status" value={status} onChange={(e) => setStatus(e.target.value as Department['status'])}>
        <option value="ACTIVE">Active</option>
        <option value="INACTIVE">Inactive</option>
      </SelectField>
      <div className="flex justify-end gap-2">
        <Button variant="secondary" onClick={onClose}>
          Cancel
        </Button>
        <Button type="submit" loading={busy}>
          {dept ? 'Save' : 'Create'}
        </Button>
      </div>
    </form>
  )
}

export function DepartmentsPage() {
  const { can } = useAuth()
  const manage = can('departments.manage')
  const [page, setPage] = useState(1)
  const [editing, setEditing] = useState<Department | 'new' | null>(null)
  const list = useResource(() => api.get<Page<Department>>('/org/departments/', { page }), [page])
  const rows = list.data?.results ?? []
  return (
    <>
      <PageHeader
        title="Departments"
        description="Organizational boundaries used for approvals and reporting."
        actions={manage && <Button onClick={() => setEditing('new')}>New department</Button>}
      />
      <ErrorBanner error={list.error} onRetry={list.reload} />
      {list.loading && <LoadingBlock />}
      {!list.loading && !list.error && rows.length === 0 && <EmptyState title="No departments yet" />}
      {rows.length > 0 && (
        <>
          <Table caption="Departments">
            <thead>
              <tr><Th>Name</Th><Th>Code</Th><Th>Status</Th><Th /></tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {rows.map((d) => (
                <tr key={d.id}>
                  <Td>{d.name}</Td>
                  <Td>{d.code}</Td>
                  <Td><Badge tone={statusTone(d.status)}>{d.status}</Badge></Td>
                  <Td>{manage && <Button variant="ghost" onClick={() => setEditing(d)} aria-label={`Edit ${d.name}`}>Edit</Button>}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
          <Pagination page={page} count={list.data?.count ?? 0} onPage={setPage} />
        </>
      )}
      <Modal open={editing !== null} onClose={() => setEditing(null)} title={editing && editing !== 'new' ? 'Edit department' : 'New department'}>
        <DepartmentForm dept={editing && editing !== 'new' ? editing : undefined} onClose={() => setEditing(null)} onSaved={list.reload} />
      </Modal>
    </>
  )
}
