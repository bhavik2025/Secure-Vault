/**
 * Thin fetch wrapper for the Django API.
 *
 * - Session auth: cookies are sent automatically (`credentials: 'same-origin'`; the Vite
 *   dev proxy and the production reverse proxy keep the SPA and API on one origin).
 * - CSRF: unsafe methods echo the `csrftoken` cookie in `X-CSRFToken`.
 * - No tokens or secrets are ever kept in JS-accessible storage.
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
  if (!res.ok) throw new ApiError(res.status, body)
  return body as T
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

export interface HealthResponse {
  status: 'ok' | 'degraded'
  database: boolean
  redis: boolean
}

export const getHealth = () => apiFetch<HealthResponse>('/health/')
export const primeCsrf = () => apiFetch<{ detail: string }>('/auth/csrf/')
