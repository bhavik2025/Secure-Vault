import { useEffect, useState } from 'react'
import { ApiError, getHealth, type HealthResponse } from './lib/api'

type State =
  | { kind: 'loading' }
  | { kind: 'ready'; health: HealthResponse }
  | { kind: 'error'; message: string }

function Badge({ ok, label }: { ok: boolean; label: string }) {
  return (
    <li className="flex items-center justify-between rounded-lg border border-slate-200 px-4 py-3 dark:border-slate-800">
      <span>{label}</span>
      <span
        className={ok ? 'font-medium text-emerald-600' : 'font-medium text-red-600'}
        role="status"
        aria-label={`${label} ${ok ? 'connected' : 'unreachable'}`}
      >
        {ok ? 'Connected' : 'Unreachable'}
      </span>
    </li>
  )
}

export default function App() {
  const [state, setState] = useState<State>({ kind: 'loading' })

  useEffect(() => {
    let cancelled = false
    getHealth()
      .then((health) => !cancelled && setState({ kind: 'ready', health }))
      .catch((err: unknown) => {
        if (cancelled) return
        // A 503 still carries a useful body (which dependency is down).
        if (err instanceof ApiError && err.body && typeof err.body === 'object') {
          setState({ kind: 'ready', health: err.body as HealthResponse })
        } else {
          setState({ kind: 'error', message: 'Cannot reach the SecureVault API.' })
        }
      })
    return () => {
      cancelled = true
    }
  }, [])

  return (
    <main className="mx-auto max-w-xl px-4 py-16">
      <h1 className="text-2xl font-semibold">SecureVault</h1>
      <p className="mt-1 text-sm text-slate-500">Foundation check: frontend ↔ backend connectivity</p>

      <section className="mt-8" aria-live="polite">
        {state.kind === 'loading' && <p>Checking services…</p>}
        {state.kind === 'error' && (
          <p role="alert" className="text-red-600">
            {state.message}
          </p>
        )}
        {state.kind === 'ready' && (
          <ul className="space-y-2">
            <Badge ok={state.health.database} label="PostgreSQL" />
            <Badge ok={state.health.redis} label="Redis" />
          </ul>
        )}
      </section>
    </main>
  )
}
