import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../lib/api'
import { cancelPendingClear, copyWithAutoClear, CLIPBOARD_CLEAR_MS } from '../lib/clipboard'
import { errorMessage } from '../lib/errors'
import type { RevealResponse } from '../lib/types'
import { Button, ConfirmDialog, FormError } from './ui'
import { useToast } from './Toast'

export const AUTO_HIDE_MS = 30_000
const MASK = '•'.repeat(12)

/**
 * Masked-by-default secret. Revealing is an explicit server-authorized action (POST .../reveal/); the
 * plaintext lives ONLY in this component's state: never in storage, never in the URL, never cached.
 * It is hidden again after 30 seconds, on unmount, and on tab change. Copying clears the clipboard after
 * 30 seconds on a best-effort basis (browsers may refuse), which the UI says plainly.
 */
export function SecretReveal({
  endpoint,
  field,
  label,
  viewOnce = false,
  multiline = false,
}: {
  endpoint: string
  field: 'password' | 'content'
  label: string
  viewOnce?: boolean
  multiline?: boolean
}) {
  const [secret, setSecret] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string>()
  const [confirming, setConfirming] = useState(false)
  const [consumed, setConsumed] = useState(false)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const { notify } = useToast()

  const hide = useCallback(() => {
    if (timer.current) clearTimeout(timer.current)
    timer.current = null
    setSecret(null)
  }, [])

  useEffect(() => {
    const onVisibility = () => {
      if (document.hidden) hide()
    }
    document.addEventListener('visibilitychange', onVisibility)
    return () => {
      document.removeEventListener('visibilitychange', onVisibility)
      if (timer.current) clearTimeout(timer.current)
    }
  }, [hide])

  async function reveal() {
    setConfirming(false)
    setLoading(true)
    setError(undefined)
    try {
      const res = await api.post<RevealResponse>(endpoint)
      const value = res[field] ?? ''
      setSecret(value)
      if (res.view_once) setConsumed(true)
      if (timer.current) clearTimeout(timer.current)
      timer.current = setTimeout(hide, AUTO_HIDE_MS)
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setLoading(false)
    }
  }

  async function copy() {
    if (secret === null) return
    try {
      await copyWithAutoClear(secret)
      notify(`Copied. The clipboard is cleared after ${CLIPBOARD_CLEAR_MS / 1000}s if the browser allows it (best-effort).`, 'info')
    } catch {
      notify('Could not copy. Your browser blocked clipboard access.', 'error')
    }
  }

  function onHide() {
    hide()
    cancelPendingClear()
  }

  return (
    <div className="space-y-3">
      <p className="text-sm font-medium text-slate-700 dark:text-slate-200">{label}</p>
      {secret === null ? (
        <div className="flex flex-wrap items-center gap-3">
          <code aria-label={`${label} (hidden)`} className="rounded-md bg-slate-100 px-3 py-2 font-mono text-sm tracking-widest dark:bg-slate-800">
            {MASK}
          </code>
          <Button
            variant="secondary"
            loading={loading}
            disabled={consumed}
            onClick={() => (viewOnce ? setConfirming(true) : void reveal())}
          >
            Reveal
          </Button>
        </div>
      ) : (
        <div className="space-y-2">
          {multiline ? (
            <pre
              data-testid="revealed-secret"
              className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-md bg-amber-50 p-3 font-mono text-sm text-slate-900 ring-1 ring-amber-200 dark:bg-amber-950 dark:text-amber-100 dark:ring-amber-900"
            >
              {secret}
            </pre>
          ) : (
            <code
              data-testid="revealed-secret"
              className="block break-all rounded-md bg-amber-50 px-3 py-2 font-mono text-sm text-slate-900 ring-1 ring-amber-200 dark:bg-amber-950 dark:text-amber-100 dark:ring-amber-900"
            >
              {secret}
            </code>
          )}
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="secondary" onClick={() => void copy()}>
              Copy
            </Button>
            <Button variant="ghost" onClick={onHide}>
              Hide
            </Button>
            <span className="text-xs text-slate-500">Hides automatically after 30 seconds.</span>
          </div>
        </div>
      )}
      {consumed && secret === null && (
        <p className="text-xs text-slate-500">This one-time access has now been used.</p>
      )}
      <FormError message={error} />
      <ConfirmDialog
        open={confirming}
        title="One-time access"
        confirmLabel="Reveal now"
        message="This was shared as a one-time view. After you reveal it, it can never be revealed again. Make sure you are ready to copy it."
        onConfirm={() => void reveal()}
        onCancel={() => setConfirming(false)}
      />
    </div>
  )
}
