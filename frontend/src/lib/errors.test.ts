import { describe, expect, it } from 'vitest'
import { ApiError } from './api'
import { errorMessage, fieldErrors, isTransient } from './errors'

describe('errorMessage', () => {
  it.each([
    ['grant_consumed', 'already been used'],
    ['lockdown_active', 'lockdown'],
    ['grant_revoked', 'revoked'],
    ['grant_expired', 'expired'],
    ['device_trust_unavailable', 'trusted device'],
    ['exceeds_upstream_lifetime', 'longer'],
    ['view_once_disabled', 'turned off'],
  ])('explains %s', (code, snippet) => {
    expect(errorMessage(new ApiError(403, { detail: 'x', code }))).toContain(snippet)
  })

  it('falls back to the server detail, then to a generic message', () => {
    expect(errorMessage(new ApiError(400, { detail: 'Custom problem' }))).toBe('Custom problem')
    expect(errorMessage(new ApiError(500, null))).toMatch(/something went wrong/i)
  })

  it('handles throttling, not-found and network failures', () => {
    expect(errorMessage(new ApiError(429, { detail: 'Request was throttled.' }))).toMatch(/too many requests/i)
    expect(errorMessage(new ApiError(404, { detail: 'Not found.' }))).toMatch(/not found/i)
    expect(errorMessage(new TypeError('Failed to fetch'))).toMatch(/cannot reach/i)
  })

  it('uses the first field error when there is no detail', () => {
    expect(errorMessage(new ApiError(400, { title: ['This field is required.'] }))).toBe('This field is required.')
  })
})

describe('isTransient', () => {
  it('offers retry only for failures that may go away', () => {
    expect(isTransient(new TypeError('Failed to fetch'))).toBe(true)
    expect(isTransient(new ApiError(503, null))).toBe(true)
    expect(isTransient(new ApiError(429, null))).toBe(true)
    for (const s of [400, 403, 404, 410, 423]) expect(isTransient(new ApiError(s, null))).toBe(false)
  })
})

describe('fieldErrors', () => {
  it('flattens DRF validation bodies', () => {
    const err = new ApiError(400, { title: ['Too short.', 'Also bad.'], base_url: ['Enter a valid URL.'], code: 'x' })
    expect(fieldErrors(err)).toEqual({ title: 'Too short. Also bad.', base_url: 'Enter a valid URL.' })
  })
  it('does not mistake the general {detail, code} body for a form field', () => {
    expect(fieldErrors(new ApiError(400, { detail: 'No such active user.', code: 'invalid_grantee' }))).toEqual({})
  })
  it('maps a list body to non_field_errors and ignores other statuses', () => {
    expect(fieldErrors(new ApiError(400, ['Archived.']))).toEqual({ non_field_errors: 'Archived.' })
    expect(fieldErrors(new ApiError(403, { title: ['x'] }))).toEqual({})
    expect(fieldErrors(new Error('boom'))).toEqual({})
  })
})
