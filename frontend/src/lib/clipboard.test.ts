import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cancelPendingClear, CLIPBOARD_CLEAR_MS, copyWithAutoClear } from './clipboard'

function fakeClipboard(initial: string | 'denied' = '') {
  let content = initial === 'denied' ? '' : initial
  const clip = {
    writeText: vi.fn(async (v: string) => {
      content = v
    }),
    readText: vi.fn(async () => {
      if (initial === 'denied') throw new DOMException('denied', 'NotAllowedError')
      return content
    }),
  }
  Object.defineProperty(navigator, 'clipboard', { value: clip, configurable: true })
  return { clip, set: (v: string) => (content = v), get: () => content }
}

beforeEach(() => vi.useFakeTimers())
afterEach(() => {
  cancelPendingClear()
  vi.useRealTimers()
})

describe('copyWithAutoClear', () => {
  it('copies now and clears after 30 seconds if the clipboard still holds the secret', async () => {
    const c = fakeClipboard()
    await copyWithAutoClear('s3cret')
    expect(c.get()).toBe('s3cret')
    await vi.advanceTimersByTimeAsync(CLIPBOARD_CLEAR_MS - 1)
    expect(c.get()).toBe('s3cret')
    await vi.advanceTimersByTimeAsync(2)
    expect(c.get()).toBe('')
  })

  it('does not wipe something else the user copied in the meantime', async () => {
    const c = fakeClipboard()
    await copyWithAutoClear('s3cret')
    c.set('their own text')
    await vi.advanceTimersByTimeAsync(CLIPBOARD_CLEAR_MS + 1)
    expect(c.get()).toBe('their own text')
  })

  it('clears anyway when the browser will not let us read the clipboard', async () => {
    const c = fakeClipboard('denied')
    await copyWithAutoClear('s3cret')
    await vi.advanceTimersByTimeAsync(CLIPBOARD_CLEAR_MS + 1)
    expect(c.clip.writeText).toHaveBeenLastCalledWith('')
  })

  it('survives a clipboard that refuses the clearing write', async () => {
    const c = fakeClipboard()
    await copyWithAutoClear('s3cret')
    c.clip.writeText.mockRejectedValueOnce(new Error('no focus'))
    await expect(vi.advanceTimersByTimeAsync(CLIPBOARD_CLEAR_MS + 1)).resolves.not.toThrow()
  })

  it('restarts the countdown on a second copy', async () => {
    const c = fakeClipboard()
    await copyWithAutoClear('first')
    await vi.advanceTimersByTimeAsync(20_000)
    await copyWithAutoClear('second')
    await vi.advanceTimersByTimeAsync(20_000) // 40s after the first copy, 20s after the second
    expect(c.get()).toBe('second')
    await vi.advanceTimersByTimeAsync(10_001)
    expect(c.get()).toBe('')
  })

  it('can be cancelled', async () => {
    const c = fakeClipboard()
    await copyWithAutoClear('s3cret')
    cancelPendingClear()
    await vi.advanceTimersByTimeAsync(CLIPBOARD_CLEAR_MS * 2)
    expect(c.get()).toBe('s3cret')
  })

  it('propagates a failed copy so the UI can tell the user', async () => {
    const clip = { writeText: vi.fn().mockRejectedValue(new Error('blocked')), readText: vi.fn() }
    Object.defineProperty(navigator, 'clipboard', { value: clip, configurable: true })
    await expect(copyWithAutoClear('x')).rejects.toThrow('blocked')
  })
})
