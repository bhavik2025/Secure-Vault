import { describe, expect, it } from 'vitest'
import { formatDate, formatDateTime, relativeTime } from './format'

describe('relativeTime', () => {
  const now = Date.parse('2026-01-10T12:00:00Z')
  it('describes the future and the past', () => {
    expect(relativeTime('2026-01-13T12:00:00Z', now)).toBe('in 3 days')
    expect(relativeTime('2026-01-10T14:00:00Z', now)).toBe('in 2 hours')
    expect(relativeTime('2026-01-10T11:55:00Z', now)).toBe('5 minutes ago')
    expect(relativeTime('2026-01-09T12:00:00Z', now)).toBe('1 day ago')
    expect(relativeTime('2026-01-10T12:00:20Z', now)).toBe('in under a minute')
    expect(relativeTime('2026-01-10T11:59:50Z', now)).toBe('just now')
  })
  it('is safe on missing or invalid input', () => {
    expect(relativeTime(null)).toBe('—')
    expect(relativeTime('not a date')).toBe('—')
  })
})

describe('date formatting', () => {
  it('shows a dash for empty or invalid values', () => {
    expect(formatDate(null)).toBe('—')
    expect(formatDateTime(undefined)).toBe('—')
    expect(formatDate('garbage')).toBe('—')
  })
  it('formats plain dates without timezone shifting the day', () => {
    expect(formatDate('2026-03-05')).toContain('5')
  })
})
