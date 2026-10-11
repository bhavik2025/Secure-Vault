import { useState, type FormEvent } from 'react'
import { useResource } from '../hooks/useResource'
import { api } from '../lib/api'
import { errorMessage, fieldErrors } from '../lib/errors'
import type { Access, EffectivePolicy, Share } from '../lib/types'
import { useToast } from './Toast'
import { Button, Checkbox, FormError, Modal, SelectField, TextField } from './ui'

const DURATIONS = [
  { value: '', label: 'No expiry (until revoked)' },
  { value: '1', label: '1 hour' },
  { value: '8', label: '8 hours' },
  { value: '24', label: '24 hours' },
  { value: '168', label: '7 days' },
  { value: '720', label: '30 days' },
]

export function ShareDialog({
  open,
  onClose,
  credentialId,
  access,
  onShared,
}: {
  open: boolean
  onClose: () => void
  credentialId: number
  access: Access
  onShared: (s: Share) => void
}) {
  return (
    <Modal open={open} onClose={onClose} title={access.role === 'owner' ? 'Share credential' : 'Delegate access'}>
      <ShareForm credentialId={credentialId} access={access} onClose={onClose} onShared={onShared} />
    </Modal>
  )
}

function ShareForm({
  credentialId,
  access,
  onClose,
  onShared,
}: {
  credentialId: number
  access: Access
  onClose: () => void
  onShared: (s: Share) => void
}) {
  const { notify } = useToast()
  const policy = useResource(() => api.get<EffectivePolicy>('/org/security-policies/active/'), [])
  const owner = access.role === 'owner'
  const [email, setEmail] = useState('')
  const [canView, setCanView] = useState(true)
  const [canEdit, setCanEdit] = useState(false)
  const [canShare, setCanShare] = useState(false)
  const [viewOnce, setViewOnce] = useState(false)
  const [hours, setHours] = useState('')
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [general, setGeneral] = useState<string>()
  const [busy, setBusy] = useState(false)

  const viewOnceAllowed = policy.data?.allow_view_once ?? true
  // What the signed-in user may hand on. Owners may grant anything; delegates only what they hold.
  const may = {
    view: owner || access.can_view,
    edit: owner || access.can_edit,
    share: owner || access.can_share,
  }

  function toggleViewOnce(on: boolean) {
    setViewOnce(on)
    if (on) {
      setCanView(true)
      setCanEdit(false)
      setCanShare(false)
    }
  }

  async function submit(e: FormEvent) {
    e.preventDefault()
    setErrors({})
    setGeneral(undefined)
    setBusy(true)
    const body: Record<string, unknown> = {
      grantee_email: email.trim(),
      can_view: canView,
      can_edit: canEdit,
      can_share: canShare,
      is_view_once: viewOnce,
    }
    if (hours) body.expires_in_hours = Number(hours)
    try {
      const share = await api.post<Share>(`/vault/credentials/${credentialId}/shares/`, body)
      notify(`Shared with ${share.grantee.email}.`)
      onShared(share)
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
      <FormError message={general ?? errors.non_field_errors} />
      <TextField
        label="Colleague's email"
        type="email"
        required
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        error={errors.grantee_email}
        hint="They must have an active account in your organization."
      />
      <fieldset className="space-y-2">
        <legend className="text-sm font-medium text-slate-700 dark:text-slate-200">Permissions</legend>
        <Checkbox label="View the secret" checked={canView} disabled={!may.view || viewOnce} onChange={(e) => setCanView(e.target.checked)} />
        <Checkbox label="Edit the credential" checked={canEdit} disabled={!may.edit || viewOnce} onChange={(e) => setCanEdit(e.target.checked)} />
        <Checkbox
          label="Share it onward"
          hint="They can then delegate to others, never more than you gave them."
          checked={canShare}
          disabled={!may.share || viewOnce}
          onChange={(e) => setCanShare(e.target.checked)}
        />
      </fieldset>
      <Checkbox
        label="One-time view"
        hint={
          viewOnceAllowed
            ? 'The secret can be revealed exactly once, then the access is used up. View-only.'
            : 'Turned off by your organization’s security policy.'
        }
        checked={viewOnce}
        disabled={!viewOnceAllowed}
        onChange={(e) => toggleViewOnce(e.target.checked)}
      />
      <SelectField
        label="Access lasts"
        value={hours}
        onChange={(e) => setHours(e.target.value)}
        error={errors.expires_in_hours}
        hint={!owner ? 'A delegated share can never outlast the share it came from.' : undefined}
      >
        {DURATIONS.map((d) => (
          <option key={d.value} value={d.value}>
            {d.label}
          </option>
        ))}
      </SelectField>
      <div className="flex justify-end gap-2 pt-2">
        <Button variant="secondary" onClick={onClose}>
          Cancel
        </Button>
        <Button type="submit" loading={busy}>
          Share
        </Button>
      </div>
    </form>
  )
}
