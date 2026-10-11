/**
 * Thin fetch wrapper for the Django API.
 *
 * - Session auth: cookies are sent automatically (`credentials: 'same-origin'`; the Vite dev proxy and a
 *   production reverse proxy keep the SPA and API on one origin).
 * - CSRF: unsafe methods echo the `csrftoken` cookie in `X-CSRFToken`.
 * - No tokens, passwords or secrets are ever kept in JS-accessible storage.
 * - Global hooks let the app react to "session ended" (403 not_authenticated) and "lockdown active" (423).
 */

export class ApiError extends Error {
  readonly status: number
  readonly body: unknown

  constructor(status: number, body: unknown) {
    super(`API request failed with status ${status}`)
    this.name = 'ApiError'
    this.status = status
    this.body = body
  }

  /** Machine-readable error code from the backend, e.g. `grant_consumed`. */
  get code(): string | undefined {
    const b = this.body
    return b && typeof b === 'object' && 'code' in b && typeof (b as { code: unknown }).code === 'string'
      ? (b as { code: string }).code
      : undefined
  }

  /** Human-readable message from the backend, when it sent one. */
  get detail(): string | undefined {
    const b = this.body
    return b && typeof b === 'object' && 'detail' in b && typeof (b as { detail: unknown }).detail === 'string'
      ? (b as { detail: string }).detail
      : undefined
  }
}

export interface ApiHooks {
  onUnauthenticated?: () => void
  onLockdown?: () => void
}

let hooks: ApiHooks = {}
export function setApiHooks(next: ApiHooks): void {
  hooks = next
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

export function readCookie(name: string, cookieString: string = document.cookie): string | null {
  for (const part of cookieString.split(';')) {
    const [k, ...rest] = part.trim().split('=')
    if (k === name) return decodeURIComponent(rest.join('='))
  }
  return null
}

export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? 'GET').toUpperCase()
  const headers = new Headers(init.headers)
  headers.set('Accept', 'application/json')
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  if (!SAFE_METHODS.has(method)) {
    const token = readCookie('csrftoken')
    if (token) headers.set('X-CSRFToken', token)
  }

  const res = await fetch(`/api${path}`, { ...init, method, headers, credentials: 'same-origin' })
  const text = await res.text()
  const body: unknown = text ? safeJson(text) : null
  if (!res.ok) {
    const err = new ApiError(res.status, body)
    if (res.status === 423 || err.code === 'lockdown_active') hooks.onLockdown?.()
    if (res.status === 403 && err.code === 'not_authenticated') hooks.onUnauthenticated?.()
    throw err
  }
  return body as T
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

export type Params = Record<string, string | number | boolean | null | undefined>

export function withQuery(path: string, params?: Params): string {
  if (!params) return path
  const q = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') q.set(k, String(v))
  }
  const s = q.toString()
  return s ? `${path}${path.includes('?') ? '&' : '?'}${s}` : path
}

const json = (body: unknown) => (body === undefined ? undefined : JSON.stringify(body))

export const api = {
  get: <T>(path: string, params?: Params) => apiFetch<T>(withQuery(path, params)),
  post: <T>(path: string, body?: unknown) => apiFetch<T>(path, { method: 'POST', body: json(body) }),
  patch: <T>(path: string, body: unknown) => apiFetch<T>(path, { method: 'PATCH', body: json(body) }),
}

export interface HealthResponse {
  status: 'ok' | 'degraded'
  database: boolean
  redis: boolean
}

export const getHealth = () => apiFetch<HealthResponse>('/health/')
export const primeCsrf = () => apiFetch<{ detail: string }>('/auth/csrf/')
