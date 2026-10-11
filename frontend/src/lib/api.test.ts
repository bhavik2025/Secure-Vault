import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, apiFetch, readCookie } from './api'

afterEach(() => vi.restoreAllMocks())

describe('readCookie', () => {
  it('finds a cookie by name', () => {
    expect(readCookie('csrftoken', 'a=1; csrftoken=abc%3D; b=2')).toBe('abc=')
  })
  it('returns null when absent', () => {
    expect(readCookie('csrftoken', 'a=1')).toBeNull()
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

  it('throws ApiError with status and parsed body on failure', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response('{"detail":"nope"}', { status: 403 }))
    await expect(apiFetch('/x/')).rejects.toMatchObject({ status: 403, body: { detail: 'nope' } })
    await expect(apiFetch('/x/')).rejects.toBeInstanceOf(ApiError)
  })
})
