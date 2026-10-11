import { useEffect, useState, type FormEvent } from 'react'
import { useResource, useDebounced } from '../hooks/useResource'
import { api } from '../lib/api'
import { errorMessage, fieldErrors } from '../lib/errors'
import { CATEGORIES, type Category, type Credential, type EffectivePolicy, type GeneratedPassword, type Page, type PasswordCheck, type ServiceEntry, type Strength } from '../lib/types'
import { StrengthMeter } from './StrengthMeter'
import { useToast } from './Toast'
import { Button, FormError, Modal, SelectField, TextField } from './ui'

interface Props {
  open: boolean
  onClose: () => void
  onSaved: (c: Credential) => void
  credential?: Credential // present = edit mode
}

export function CredentialFormModal({ open, onClose, onSaved, credential }: Props) {
  return (
    <Modal open={open} onClose={onClose} title={credential ? 'Edit credential' : 'New credential'} wide>
      <CredentialForm credential={credential} onClose={onClose} onSaved={onSaved} />
    </Modal>
  )
}

function CredentialForm({ credential, onClose, onSaved }: Omit<Props, 'open'>) {
  const editing = !!credential
  const { notify } = useToast()
  const services = useResource(() => api.get<Page<ServiceEntry>>('/org/services/', { status: 'ACTIVE' }), [])
  const policy = useResource(() => api.get<EffectivePolicy>('/org/security-policies/active/'), [])

  const [title, setTitle] = useState(credential?.title ?? '')
  const [service, setService] = useState(credential?.service ? String(credential.service) : '')
  const [username, setUsername] = useState(credential?.username ?? '')
  const [password, setPassword] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [category, setCategory] = useState<Category>(credential?.category ?? 'OTHER')
  const [tags, setTags] = useState(credential?.tags.join(', ') ?? '')
  const [expiry, setExpiry] = useState(credential?.expiry_date ?? '')
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [general, setGeneral] = useState<string>()
  const [busy, setBusy] = useState(false)
  const [checked, setChecked] = useState<{ pw: string; strength: Strength; violations: string[] } | null>(null)
  const [generating, setGenerating] = useState(false)

  const debouncedPw = useDebounced(password, 600)
  useEffect(() => {
    if (!debouncedPw) return
    let cancelled = false
    api
      .post<PasswordCheck>('/vault/password/check/', { password: debouncedPw })
      .then((r) => {
        if (cancelled) return
        setChecked({ pw: debouncedPw, strength: r.strength, violations: r.policy_violations })
      })
      .catch(() => undefined) // rate-limited or offline: the server re-validates on save anyway
    return () => {
      cancelled = true
    }
  }, [debouncedPw])

  async function generate() {
    setGenerating(true)
    setGeneral(undefined)
    try {
      const r = await api.post<GeneratedPassword>('/vault/password/generate/', {})
      setPassword(r.password)
      setShowPw(true)
      setChecked({ pw: r.password, strength: r.strength, violations: [] })
    } catch (e) {
      setGeneral(errorMessage(e))
    } finally {
      setGenerating(false)
    }
  }

  async function submit(e: FormEvent) {
    e.preventDefault()
    setErrors({})
    setGeneral(undefined)
    setBusy(true)
    const tagList = tags.split(',').map((t) => t.trim()).filter(Boolean)
    try {
      let saved: Credential
      if (editing) {
        const body: Record<string, unknown> = {
          title,
          username,
          category,
          tags: tagList,
          service: service ? Number(service) : null,
        }
        if (password) body.password = password
        if (expiry !== (credential?.expiry_date ?? '')) body.expiry_date = expiry || null
        saved = await api.patch<Credential>(`/vault/credentials/${credential!.id}/`, body)
      } else {
        const body: Record<string, unknown> = { title, username, password, category, tags: tagList }
        if (service) body.service = Number(service)
        if (expiry) body.expiry_date = expiry
        saved = await api.post<Credential>('/vault/credentials/', body)
      }
      setPassword('')
      notify(editing ? 'Credential updated.' : 'Credential created.')
      onSaved(saved)
      onClose()
    } catch (err) {
      const f = fieldErrors(err)
      setErrors(f)
      setGeneral(Object.keys(f).length ? undefined : errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const p = policy.data
  // Only show feedback that belongs to the password currently in the box.
  const feedback = password && checked && checked.pw === password ? checked : null
  const strength = feedback?.strength ?? null
  const violations = feedback?.violations ?? []
  return (
    <form onSubmit={(e) => void submit(e)} className="space-y-4">
      <FormError message={general ?? errors.non_field_errors} />
      <div className="grid gap-4 sm:grid-cols-2">
        <TextField label="Title" required value={title} onChange={(e) => setTitle(e.target.value)} error={errors.title} />
        <SelectField label="Service" value={service} onChange={(e) => setService(e.target.value)} error={errors.service}>
          <option value="">No service</option>
          {services.data?.results.map((s) => (
            <option key={s.id} value={s.id}>
              {s.name}
            </option>
          ))}
        </SelectField>
        <TextField label="Username" value={username} onChange={(e) => setUsername(e.target.value)} error={errors.username} autoComplete="off" />
        <SelectField label="Category" value={category} onChange={(e) => setCategory(e.target.value as Category)} error={errors.category}>
          {CATEGORIES.map((c) => (
            <option key={c.value} value={c.value}>
              {c.label}
            </option>
          ))}
        </SelectField>
      </div>

      <div className="space-y-2">
        <div className="flex items-end gap-2">
          <div className="flex-1">
            <TextField
              label={editing ? 'New password' : 'Password'}
              type={showPw ? 'text' : 'password'}
              autoComplete="new-password"
              required={!editing}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              error={errors.password}
              hint={
                editing
                  ? 'Leave blank to keep the current password.'
                  : p
                    ? `At least ${p.min_length} characters${p.require_symbols ? ' including a symbol' : ''}.`
                    : undefined
              }
            />
          </div>
          <Button variant="secondary" onClick={() => setShowPw((s) => !s)} aria-pressed={showPw}>
            {showPw ? 'Hide' : 'Show'}
          </Button>
          <Button variant="secondary" loading={generating} onClick={() => void generate()}>
            Generate
          </Button>
        </div>
        <StrengthMeter strength={strength} />
        {violations.length > 0 && (
          <ul className="list-disc pl-5 text-xs text-amber-700 dark:text-amber-400">
            {violations.map((v) => (
              <li key={v}>{v}</li>
            ))}
          </ul>
        )}
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <TextField
          label="Tags"
          value={tags}
          onChange={(e) => setTags(e.target.value)}
          error={errors.tags}
          hint="Comma-separated, e.g. prod, database"
        />
        <TextField
          label="Expiry date"
          type="date"
          value={expiry}
          onChange={(e) => setExpiry(e.target.value)}
          error={errors.expiry_date}
          hint={p?.max_age_days ? `Optional. Defaults to ${p.max_age_days} days; policy maximum is ${p.max_age_days} days.` : 'Optional.'}
        />
      </div>

      <div className="flex justify-end gap-2 pt-2">
        <Button variant="secondary" onClick={onClose}>
          Cancel
        </Button>
        <Button type="submit" loading={busy}>
          {editing ? 'Save changes' : 'Create credential'}
        </Button>
      </div>
    </form>
  )
}
