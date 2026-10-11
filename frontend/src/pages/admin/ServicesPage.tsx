import { useState, type FormEvent } from 'react'
import { useAuth } from '../../auth/AuthContext'
import { useToast } from '../../components/Toast'
import {
  Badge, Button, EmptyState, ErrorBanner, FormError, LoadingBlock, Modal, PageHeader, Pagination, SelectField, Table, Td, Th,
  TextField, statusTone,
} from '../../components/ui'
import { useDebounced, usePageState, useResource } from '../../hooks/useResource'
import { api } from '../../lib/api'
import { errorMessage, fieldErrors } from '../../lib/errors'
import { CATEGORIES, type Category, type Page, type ServiceEntry } from '../../lib/types'

function ServiceForm({ service, onClose, onSaved }: { service?: ServiceEntry; onClose: () => void; onSaved: () => void }) {
  const { notify } = useToast()
  const [name, setName] = useState(service?.name ?? '')
  const [category, setCategory] = useState<Category>(service?.category ?? 'OTHER')
  const [baseUrl, setBaseUrl] = useState(service?.base_url ?? '')
  const [iconUrl, setIconUrl] = useState(service?.icon_url ?? '')
  const [port, setPort] = useState(service?.default_port ? String(service.default_port) : '')
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [general, setGeneral] = useState<string>()
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setErrors({})
    setGeneral(undefined)
    const body = { name, category, base_url: baseUrl, icon_url: iconUrl, default_port: port ? Number(port) : null }
    try {
      if (service) await api.patch(`/org/services/${service.id}/`, body)
      else await api.post('/org/services/', body)
      notify(service ? 'Service updated.' : 'Service created.')
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
      <SelectField label="Category" value={category} onChange={(e) => setCategory(e.target.value as Category)} error={errors.category}>
        {CATEGORIES.map((c) => (
          <option key={c.value} value={c.value}>{c.label}</option>
        ))}
      </SelectField>
      <TextField
        label="Base URL"
        required
        value={baseUrl}
        onChange={(e) => setBaseUrl(e.target.value)}
        error={errors.base_url}
        hint="http, https, ssh, sftp, postgresql, mysql, mongodb or redis. No embedded credentials."
        placeholder="https://console.example.com"
      />
      <TextField label="Icon URL (optional)" value={iconUrl} onChange={(e) => setIconUrl(e.target.value)} error={errors.icon_url} hint="https only" />
      <TextField label="Default port (optional)" type="number" min={1} max={65535} value={port} onChange={(e) => setPort(e.target.value)} error={errors.default_port} />
      <div className="flex justify-end gap-2">
        <Button variant="secondary" onClick={onClose}>Cancel</Button>
        <Button type="submit" loading={busy}>{service ? 'Save' : 'Create'}</Button>
      </div>
    </form>
  )
}

export function ServicesPage() {
  const { can } = useAuth()
  const { notify } = useToast()
  const manage = can('services.manage')
  const [q, setQ] = useState('')
  const [status, setStatus] = useState('')
  const [editing, setEditing] = useState<ServiceEntry | 'new' | null>(null)
  const dq = useDebounced(q)
  const [page, setPage] = usePageState(JSON.stringify([dq, status]))
  const list = useResource(() => api.get<Page<ServiceEntry>>('/org/services/', { q: dq, status, page }), [dq, status, page])
  const rows = list.data?.results ?? []

  async function toggle(s: ServiceEntry) {
    try {
      await api.post(`/org/services/${s.id}/${s.status === 'ACTIVE' ? 'deactivate' : 'activate'}/`)
      notify(s.status === 'ACTIVE' ? `${s.name} deactivated.` : `${s.name} reactivated.`)
      list.reload()
    } catch (e) {
      notify(errorMessage(e), 'error')
    }
  }

  return (
    <>
      <PageHeader
        title="Service catalog"
        description="The tools and systems credentials belong to. Services are deactivated, never deleted."
        actions={manage && <Button onClick={() => setEditing('new')}>New service</Button>}
      />
      <div className="mb-4 grid gap-3 sm:grid-cols-3">
        <TextField label="Search" type="search" value={q} onChange={(e) => setQ(e.target.value)} />
        {manage && (
          <SelectField label="Status" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All</option>
            <option value="ACTIVE">Active</option>
            <option value="INACTIVE">Inactive</option>
          </SelectField>
        )}
      </div>
      <ErrorBanner error={list.error} onRetry={list.reload} />
      {list.loading && <LoadingBlock />}
      {!list.loading && !list.error && rows.length === 0 && <EmptyState title="No services found" />}
      {rows.length > 0 && (
        <>
          <Table caption="Service catalog">
            <thead>
              <tr><Th>Name</Th><Th>Category</Th><Th>Base URL</Th><Th>Port</Th><Th>Status</Th><Th /></tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {rows.map((s) => (
                <tr key={s.id}>
                  <Td>{s.name}</Td>
                  <Td>{CATEGORIES.find((c) => c.value === s.category)?.label ?? s.category}</Td>
                  <Td className="font-mono text-xs">{s.base_url}</Td>
                  <Td>{s.default_port ?? '—'}</Td>
                  <Td><Badge tone={statusTone(s.status)}>{s.status}</Badge></Td>
                  <Td>
                    {manage && (
                      <span className="flex gap-1">
                        <Button variant="ghost" onClick={() => setEditing(s)} aria-label={`Edit ${s.name}`}>Edit</Button>
                        <Button variant="ghost" onClick={() => void toggle(s)} aria-label={`${s.status === 'ACTIVE' ? 'Deactivate' : 'Activate'} ${s.name}`}>
                          {s.status === 'ACTIVE' ? 'Deactivate' : 'Activate'}
                        </Button>
                      </span>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
          <Pagination page={page} count={list.data?.count ?? 0} onPage={setPage} />
        </>
      )}
      <Modal open={editing !== null} onClose={() => setEditing(null)} title={editing && editing !== 'new' ? 'Edit service' : 'New service'}>
        <ServiceForm service={editing && editing !== 'new' ? editing : undefined} onClose={() => setEditing(null)} onSaved={list.reload} />
      </Modal>
    </>
  )
}
