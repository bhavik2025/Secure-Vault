import { useState, type FormEvent } from 'react'
import { useAuth } from '../../auth/AuthContext'
import { useToast } from '../../components/Toast'
import {
  Badge, Button, Card, Checkbox, EmptyState, ErrorBanner, FormError, LoadingBlock, Modal, PageHeader, Table, Td, Th, TextField,
} from '../../components/ui'
import { useResource } from '../../hooks/useResource'
import { api } from '../../lib/api'
import { errorMessage, fieldErrors } from '../../lib/errors'
import type { Page, SecurityPolicy } from '../../lib/types'

function PolicyForm({ policy, onClose, onSaved }: { policy?: SecurityPolicy; onClose: () => void; onSaved: () => void }) {
  const { notify } = useToast()
  const [name, setName] = useState(policy?.name ?? '')
  const [minLength, setMinLength] = useState(String(policy?.min_length ?? 12))
  const [symbols, setSymbols] = useState(policy?.require_symbols ?? true)
  const [neverExpires, setNeverExpires] = useState(policy ? policy.max_age_days === null : false)
  const [maxAge, setMaxAge] = useState(String(policy?.max_age_days ?? 90))
  const [viewOnce, setViewOnce] = useState(policy?.allow_view_once ?? true)
  const [deviceTrust, setDeviceTrust] = useState(policy?.require_device_trust ?? false)
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [general, setGeneral] = useState<string>()
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setErrors({})
    setGeneral(undefined)
    const body = {
      name,
      min_length: Number(minLength),
      require_symbols: symbols,
      max_age_days: neverExpires ? null : Number(maxAge),
      allow_view_once: viewOnce,
      require_device_trust: deviceTrust,
    }
    try {
      if (policy) await api.patch(`/org/security-policies/${policy.id}/`, body)
      else await api.post('/org/security-policies/', body)
      notify(policy ? 'Policy updated.' : 'Policy created.')
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
      <TextField label="Policy name" required value={name} onChange={(e) => setName(e.target.value)} error={errors.name} />
      <TextField label="Minimum password length" type="number" min={8} max={128} required value={minLength} onChange={(e) => setMinLength(e.target.value)} error={errors.min_length} hint="8 to 128 characters." />
      <Checkbox label="Require at least one symbol" checked={symbols} onChange={(e) => setSymbols(e.target.checked)} />
      <Checkbox label="Credentials never expire" checked={neverExpires} onChange={(e) => setNeverExpires(e.target.checked)} />
      {!neverExpires && (
        <TextField label="Maximum credential age (days)" type="number" min={1} max={730} required value={maxAge} onChange={(e) => setMaxAge(e.target.value)} error={errors.max_age_days} hint="1 to 730 days. Also the default expiry for new credentials." />
      )}
      <Checkbox label="Allow one-time (view-once) sharing" checked={viewOnce} onChange={(e) => setViewOnce(e.target.checked)} />
      <Checkbox
        label="Require a trusted device to reveal secrets"
        hint="Device registration is not built yet, so enabling this currently blocks secret reveal for everyone."
        checked={deviceTrust}
        onChange={(e) => setDeviceTrust(e.target.checked)}
      />
      <div className="flex justify-end gap-2">
        <Button variant="secondary" onClick={onClose}>Cancel</Button>
        <Button type="submit" loading={busy}>{policy ? 'Save' : 'Create'}</Button>
      </div>
    </form>
  )
}

export function PoliciesPage() {
  const { can } = useAuth()
  const { notify } = useToast()
  const manage = can('policies.manage')
  const [editing, setEditing] = useState<SecurityPolicy | 'new' | null>(null)
  const list = useResource(() => api.get<Page<SecurityPolicy>>('/org/security-policies/'), [])
  const rows = list.data?.results ?? []
  const active = rows.find((p) => p.is_active)

  async function activate(p: SecurityPolicy) {
    try {
      await api.post(`/org/security-policies/${p.id}/activate/`)
      notify(`"${p.name}" is now the active policy.`)
      list.reload()
    } catch (e) {
      notify(errorMessage(e), 'error')
    }
  }

  return (
    <>
      <PageHeader
        title="Security policies"
        description="One policy is active at a time. Changes to the active policy apply immediately, enforced by the server."
        actions={manage && <Button onClick={() => setEditing('new')}>New policy</Button>}
      />
      <ErrorBanner error={list.error} onRetry={list.reload} />
      {list.loading && <LoadingBlock />}
      {active && (
        <div className="mb-6">
          <Card title={`Active: ${active.name}`}>
            <ul className="grid gap-1 text-sm text-slate-700 sm:grid-cols-2 dark:text-slate-300">
              <li>Minimum length: {active.min_length}</li>
              <li>Symbols required: {active.require_symbols ? 'yes' : 'no'}</li>
              <li>Maximum credential age: {active.max_age_days ? `${active.max_age_days} days` : 'none'}</li>
              <li>One-time sharing: {active.allow_view_once ? 'allowed' : 'off'}</li>
              <li>Trusted device required: {active.require_device_trust ? 'yes' : 'no'}</li>
            </ul>
          </Card>
        </div>
      )}
      {!list.loading && !list.error && rows.length === 0 && <EmptyState title="No policies" />}
      {rows.length > 0 && (
        <Table caption="All security policies">
          <thead>
            <tr><Th>Name</Th><Th>Min length</Th><Th>Max age</Th><Th>One-time</Th><Th>Device trust</Th><Th>State</Th><Th /></tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
            {rows.map((p) => (
              <tr key={p.id}>
                <Td>{p.name}</Td>
                <Td>{p.min_length}{p.require_symbols ? ' + symbol' : ''}</Td>
                <Td>{p.max_age_days ? `${p.max_age_days}d` : 'none'}</Td>
                <Td>{p.allow_view_once ? 'yes' : 'no'}</Td>
                <Td>{p.require_device_trust ? 'required' : 'no'}</Td>
                <Td>{p.is_active ? <Badge tone="good">Active</Badge> : <Badge>Inactive</Badge>}</Td>
                <Td>
                  {manage && (
                    <span className="flex gap-1">
                      <Button variant="ghost" onClick={() => setEditing(p)} aria-label={`Edit ${p.name}`}>Edit</Button>
                      {!p.is_active && <Button variant="ghost" onClick={() => void activate(p)} aria-label={`Activate ${p.name}`}>Activate</Button>}
                    </span>
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      <Modal open={editing !== null} onClose={() => setEditing(null)} title={editing && editing !== 'new' ? 'Edit policy' : 'New policy'}>
        <PolicyForm policy={editing && editing !== 'new' ? editing : undefined} onClose={() => setEditing(null)} onSaved={list.reload} />
      </Modal>
    </>
  )
}
