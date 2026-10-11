import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'

type Kind = 'success' | 'error' | 'info'
interface Toast {
  id: number
  kind: Kind
  message: string
}
interface ToastApi {
  notify: (message: string, kind?: Kind) => void
}

const ToastContext = createContext<ToastApi | null>(null)
let nextId = 1

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const notify = useCallback((message: string, kind: Kind = 'success') => {
    setToasts((t) => [...t, { id: nextId++, kind, message }])
  }, [])
  const api = useMemo(() => ({ notify }), [notify])
  return (
    <ToastContext.Provider value={api}>
      {children}
      <div aria-live="polite" className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-80 flex-col gap-2">
        {toasts.map((t) => (
          <ToastItem key={t.id} toast={t} onDone={() => setToasts((all) => all.filter((x) => x.id !== t.id))} />
        ))}
      </div>
    </ToastContext.Provider>
  )
}

function ToastItem({ toast, onDone }: { toast: Toast; onDone: () => void }) {
  useEffect(() => {
    const timer = setTimeout(onDone, 6000)
    return () => clearTimeout(timer)
  }, [onDone])
  const tone =
    toast.kind === 'error' ? 'bg-red-600' : toast.kind === 'info' ? 'bg-slate-800' : 'bg-emerald-600'
  return (
    <div role="status" className={`pointer-events-auto rounded-lg px-4 py-3 text-sm text-white shadow-lg ${tone}`}>
      {toast.message}
    </div>
  )
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used inside <ToastProvider>')
  return ctx
}
