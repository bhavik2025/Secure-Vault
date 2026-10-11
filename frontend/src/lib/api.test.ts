import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api, apiFetch, readCookie, setApiHooks, withQuery } from './api'

afterEach(() => {
  vi.restoreAllMocks()
  setApiHooks({})
})

const respond = (status: number, body: unknown) => async () =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

describe('readCookie', () => {
  it('finds a cookie by name', () => {
    expect(readCookie('csrftoken', 'a=1; csrftoken=abc%3D; b=2')).toBe('abc=')
  })
  it('returns null when absent', () => {
    expect(readCookie('csrftoken', 'a=1')).toBeNull()
  })
})

describe('withQuery', () => {
  it('drops empty values and encodes the rest', () => {
    expect(withQuery('/x/', { q: 'a b', page: 2, empty: '', none: undefined, nil: null })).toBe('/x/?q=a+b&page=2')
    expect(withQuery('/x/')).toBe('/x/')
    expect(withQuery('/x/', { a: '' })).toBe('/x/')
  })
})

describe('apiFetch', () => {
  it('adds X-CSRFToken on unsafe methods only', async () => {
    document.cookie = 'csrftoken=tok123'
    const spy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response('{}', { status: 200 }))

    await apiFetch('/x/', { method: 'POST', body: '{}' })
    await apiFetch('/x/')

    const post = new Headers(spy.mock.calls[0][1]?.headers)
    const get = new Headers(spy.mock.calls[1][1]?.headers)
    expect(post.get('X-CSRFToken')).toBe('tok123')
    expect(get.has('X-CSRFToken')).toBe(false)
  })

  it('sends cookies same-origin and prefixes /api', async () => {
    const spy = vi.spyOn(globalThis, 'fetch').mockImplementation(respond(200, {}))
    await api.get('/vault/credentials/', { q: 'db' })
    expect(spy.mock.calls[0][0]).toBe('/api/vault/credentials/?q=db')
    expect(spy.mock.calls[0][1]?.credentials).toBe('same-origin')
  })

  it('throws ApiError exposing status, code and detail', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(respond(410, { detail: 'used', code: 'grant_consumed' }))
    const err = await apiFetch('/x/').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err).toMatchObject({ status: 410, code: 'grant_consumed', detail: 'used' })
  })

  it('tolerates empty and non-JSON bodies', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(null, { status: 204 }))
    expect(await apiFetch('/x/', { method: 'POST' })).toBeNull()
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response('<html>', { status: 502 }))
    await expect(apiFetch('/x/')).rejects.toMatchObject({ status: 502, body: null })
  })

  it('notifies the app when a lockdown blocks a request', async () => {
    const onLockdown = vi.fn()
    setApiHooks({ onLockdown })
    vi.spyOn(globalThis, 'fetch').mockImplementation(respond(423, { detail: 'locked', code: 'lockdown_active' }))
    await expect(api.post('/vault/credentials/1/reveal/')).rejects.toBeInstanceOf(ApiError)
    expect(onLockdown).toHaveBeenCalledOnce()
  })

  it('notifies the app when the session has ended, but not for ordinary permission errors', async () => {
    const onUnauthenticated = vi.fn()
    setApiHooks({ onUnauthenticated })
    vi.spyOn(globalThis, 'fetch').mockImplementation(respond(403, { detail: 'x', code: 'not_authenticated' }))
    await expect(api.get('/auth/me/')).rejects.toBeInstanceOf(ApiError)
    expect(onUnauthenticated).toHaveBeenCalledOnce()

    vi.spyOn(globalThis, 'fetch').mockImplementation(respond(403, { detail: 'no', code: 'view_not_granted' }))
    await expect(api.get('/x/')).rejects.toBeInstanceOf(ApiError)
    expect(onUnauthenticated).toHaveBeenCalledOnce()
  })
})
