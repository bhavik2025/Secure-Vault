import { useState, type FormEvent } from 'react'
import { SecretReveal } from '../components/SecretReveal'
import { useToast } from '../components/Toast'
import {
  Badge, Button, Card, ConfirmDialog, EmptyState, ErrorBanner, FormError, LoadingBlock, Modal, PageHeader, Pagination,
  SelectField, TextAreaField, TextField,
} from '../components/ui'
import { useDebounced, usePageState, useResource } from '../hooks/useResource'
import { api } from '../lib/api'
import { errorMessage, fieldErrors } from '../lib/errors'
import { CATEGORY_LABELS, formatDateTime } from '../lib/format'
import { CATEGORIES, type Category, type Page, type SecureNote } from '../lib/types'

function NoteForm({ note, onClose, onSaved }: { note?: SecureNote; onClose: () => void; onSaved: () => void }) {
  const { notify } = useToast()
  const [title, setTitle] = useState(note?.title ?? '')
  const [content, setContent] = useState('')
  const [category, setCategory] = useState<Category>(note?.category ?? 'OTHER')
  const [tags, setTags] = useState(note?.tags.join(', ') ?? '')
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [general, setGeneral] = useState<string>()
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setErrors({})
    setGeneral(undefined)
    const body: Record<string, unknown> = { title, category, tags: tags.split(',').map((t) => t.trim()).filter(Boolean) }
    if (content) body.content = content
    try {
      if (note) await api.patch(`/vault/notes/${note.id}/`, body)
      else await api.post('/vault/notes/', body)
      setContent('')
      notify(note ? 'Note updated.' : 'Note created.')
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
      <FormError message={general ?? errors.non_field_errors} />
      <TextField label="Title" required value={title} onChange={(e) => setTitle(e.target.value)} error={errors.title} />
      <TextAreaField
        label={note ? 'New content' : 'Content'}
        required={!note}
        rows={8}
        value={content}
        onChange={(e) => setContent(e.target.value)}
        error={errors.content}
        hint={note ? 'Leave blank to keep the current content.' : 'Encrypted before it is stored. Up to 20,000 characters.'}
      />
      <div className="grid gap-4 sm:grid-cols-2">
        <SelectField label="Category" value={category} onChange={(e) => setCategory(e.target.value as Category)}>
          {CATEGORIES.map((c) => (
            <option key={c.value} value={c.value}>
              {c.label}
            </option>
          ))}
        </SelectField>
        <TextField label="Tags" value={tags} onChange={(e) => setTags(e.target.value)} error={errors.tags} hint="Comma-separated" />
      </div>
      <div className="flex justify-end gap-2">
        <Button variant="secondary" onClick={onClose}>
          Cancel
        </Button>
        <Button type="submit" loading={busy}>
          {note ? 'Save changes' : 'Create note'}
        </Button>
      </div>
    </form>
  )
}

export function NotesPage() {
  const { notify } = useToast()
  const [q, setQ] = useState('')
  const [status, setStatus] = useState<'ACTIVE' | 'ARCHIVED'>('ACTIVE')
  const [editing, setEditing] = useState<SecureNote | 'new' | null>(null)
  const [archiving, setArchiving] = useState<SecureNote | null>(null)
  const dq = useDebounced(q)
  const [page, setPage] = usePageState(JSON.stringify([dq, status]))
  const list = useResource(() => api.get<Page<SecureNote>>('/vault/notes/', { q: dq, status, page }), [dq, status, page])

  async function toggleArchive(n: SecureNote) {
    try {
      await api.post(`/vault/notes/${n.id}/${n.status === 'ACTIVE' ? 'archive' : 'unarchive'}/`)
      notify(n.status === 'ACTIVE' ? 'Note archived.' : 'Note restored.')
      setArchiving(null)
      list.reload()
    } catch (e) {
      notify(errorMessage(e), 'error')
    }
  }

  const rows = list.data?.results ?? []
  return (
    <>
      <PageHeader
        title="Secure notes"
        description="API keys, license tokens and operational notes, encrypted at rest. Only you can reveal them."
        actions={<Button onClick={() => setEditing('new')}>New note</Button>}
      />
      <div className="mb-4 grid gap-3 sm:grid-cols-3">
        <TextField label="Search" type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Title" />
        <SelectField label="Show" value={status} onChange={(e) => setStatus(e.target.value as 'ACTIVE' | 'ARCHIVED')}>
          <option value="ACTIVE">Active</option>
          <option value="ARCHIVED">Archived</option>
        </SelectField>
      </div>
      <ErrorBanner error={list.error} onRetry={list.reload} />
      {list.loading && <LoadingBlock label="Loading notes…" />}
      {!list.loading && !list.error && rows.length === 0 && (
        <EmptyState title={q ? 'No notes match your search' : 'No notes yet'}>Create a note to store a token or configuration securely.</EmptyState>
      )}
      <div className="grid gap-4 lg:grid-cols-2">
        {rows.map((n) => (
          <Card
            key={n.id}
            title={n.title}
            actions={
              <div className="flex gap-1">
                {n.status === 'ACTIVE' && (
                  <Button variant="ghost" onClick={() => setEditing(n)} aria-label={`Edit ${n.title}`}>
                    Edit
                  </Button>
                )}
                <Button variant="ghost" onClick={() => (n.status === 'ACTIVE' ? setArchiving(n) : void toggleArchive(n))} aria-label={`${n.status === 'ACTIVE' ? 'Archive' : 'Restore'} ${n.title}`}>
                  {n.status === 'ACTIVE' ? 'Archive' : 'Restore'}
                </Button>
              </div>
            }
          >
            <div className="mb-3 flex flex-wrap items-center gap-2 text-xs text-slate-500">
              <Badge>{CATEGORY_LABELS[n.category] ?? n.category}</Badge>
              {n.tags.map((t) => (
                <span key={t}>#{t}</span>
              ))}
              <span>Updated {formatDateTime(n.updated_at)}</span>
            </div>
            {n.status === 'ACTIVE' ? (
              <SecretReveal endpoint={`/vault/notes/${n.id}/reveal/`} field="content" label="Content" multiline />
            ) : (
              <p className="text-sm text-slate-500">Restore this note to reveal its content.</p>
            )}
          </Card>
        ))}
      </div>
      {!list.loading && <Pagination page={page} count={list.data?.count ?? 0} onPage={setPage} />}

      <Modal open={editing !== null} onClose={() => setEditing(null)} title={editing && editing !== 'new' ? 'Edit note' : 'New note'} wide>
        <NoteForm note={editing && editing !== 'new' ? editing : undefined} onClose={() => setEditing(null)} onSaved={list.reload} />
      </Modal>
      <ConfirmDialog
        open={!!archiving}
        title="Archive this note?"
        confirmLabel="Archive"
        message="It will be hidden and its content can no longer be revealed until you restore it."
        onConfirm={() => archiving && void toggleArchive(archiving)}
        onCancel={() => setArchiving(null)}
      />
    </>
  )
}
