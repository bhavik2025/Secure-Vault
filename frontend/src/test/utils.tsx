import { render } from '@testing-library/react'
import type { ReactElement } from 'react'
import { MemoryRouter } from 'react-router-dom'
import { vi } from 'vitest'
import { AuthProvider } from '../auth/AuthContext'
import { ToastProvider } from '../components/Toast'
import type { Me } from '../lib/types'

export function me(over: Partial<Me> = {}): Me {
  return {
    id: 1,
    email: 'ada@acme.example',
    full_name: 'Ada Lovelace',
    organization: { id: 1, name: 'Acme' },
    department: null,
    roles: ['EMPLOYEE'],
    permissions: ['org.view', 'services.view', 'vault.use'],
    ...over,
  }
}

export const ADMIN_PERMS = [
  'org.view', 'departments.view', 'departments.manage', 'users.view', 'users.manage', 'audit.view', 'policies.view',
  'policies.manage', 'services.view', 'services.manage', 'vault.use',
]

export const page = <T,>(results: T[], count = results.length) => ({ count, next: null, previous: null, results })

export const fail = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

type Handler = unknown | ((req: { url: URL; method: string; body: unknown }) => unknown)

export interface Call {
  method: string
  path: string
  query: Record<string, string>
  body: unknown
}

/** Route-table fetch mock. Keys look like `GET /api/vault/credentials/`. Values: a JSON body (200), a Response
 *  (use `fail(status, body)`), or a function returning either. Unmatched requests return 404 and are recorded. */
export function mockApi(routes: Record<string, Handler>) {
  const calls: Call[] = []
  const spy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = new URL(typeof input === 'string' ? input : (input as Request).url, 'http://localhost')
    const method = (init?.method ?? 'GET').toUpperCase()
    const body = init?.body ? JSON.parse(String(init.body)) : undefined
    calls.push({ method, path: url.pathname, query: Object.fromEntries(url.searchParams), body })
    const handler = routes[`${method} ${url.pathname}`]
    if (handler === undefined) return fail(404, { detail: `unmocked ${method} ${url.pathname}` })
    const value = typeof handler === 'function' ? (handler as (r: unknown) => unknown)({ url, method, body }) : handler
    if (value instanceof Response) return value
    return new Response(JSON.stringify(value), { status: 200, headers: { 'Content-Type': 'application/json' } })
  })
  return {
    calls,
    spy,
    find: (method: string, path: string) => calls.filter((c) => c.method === method && c.path === path),
  }
}

export function renderApp(ui: ReactElement, { route = '/' }: { route?: string } = {}) {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <ToastProvider>
        <AuthProvider>{ui}</AuthProvider>
      </ToastProvider>
    </MemoryRouter>,
  )
}

/** Render without auth (components that only need toasts + router). */
export function renderPlain(ui: ReactElement, { route = '/' }: { route?: string } = {}) {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <ToastProvider>{ui}</ToastProvider>
    </MemoryRouter>,
  )
}
