import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { api, primeCsrf, setApiHooks } from '../lib/api'
import type { Me } from '../lib/types'

type Status = 'loading' | 'authenticated' | 'anonymous'

interface AuthValue {
  status: Status
  user: Me | null
  lockdown: boolean
  dismissLockdown: () => void
  login: (email: string, password: string) => Promise<void>
  logout: () => Promise<void>
  /** UI hint only. The server re-checks every permission on every request. */
  can: (permission: string) => boolean
}

const AuthContext = createContext<AuthValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status>('loading')
  const [user, setUser] = useState<Me | null>(null)
  const [lockdown, setLockdown] = useState(false)

  useEffect(() => {
    setApiHooks({
      onUnauthenticated: () => {
        setUser(null)
        setStatus('anonymous')
      },
      onLockdown: () => setLockdown(true),
    })
    let cancelled = false
    api
      .get<Me>('/auth/me/')
      .then((me) => {
        if (cancelled) return
        setUser(me)
        setStatus('authenticated')
      })
      .catch(() => {
        if (cancelled) return
        setStatus('anonymous')
      })
    return () => {
      cancelled = true
    }
  }, [])

  const login = useCallback(async (email: string, password: string) => {
    await primeCsrf() // sets the csrftoken cookie; login itself requires CSRF
    const me = await api.post<Me>('/auth/login/', { email, password })
    setUser(me)
    setStatus('authenticated')
    setLockdown(false)
  }, [])

  const logout = useCallback(async () => {
    try {
      await api.post('/auth/logout/')
    } finally {
      setUser(null)
      setStatus('anonymous')
    }
  }, [])

  const value = useMemo<AuthValue>(
    () => ({
      status,
      user,
      lockdown,
      dismissLockdown: () => setLockdown(false),
      login,
      logout,
      can: (p) => !!user?.permissions.includes(p),
    }),
    [status, user, lockdown, login, logout],
  )
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}
