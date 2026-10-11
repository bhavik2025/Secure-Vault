import { act, fireEvent, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cancelPendingClear } from '../lib/clipboard'
import { fail, mockApi, renderPlain } from '../test/utils'
import { AUTO_HIDE_MS, SecretReveal } from './SecretReveal'

const URL_ = '/api/vault/credentials/7/reveal/'
const SECRET = 'Zx9#kLm2$Qw8!'

afterEach(() => {
  cancelPendingClear()
  vi.useRealTimers()
  vi.restoreAllMocks()
})

async function click(name: RegExp | string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }))
  })
}

function setup(props: Partial<React.ComponentProps<typeof SecretReveal>> = {}, route: unknown = { password: SECRET, via: 'owner', view_once: false, grant_id: null }) {
  const api = mockApi({ [`POST ${URL_}`]: route })
  renderPlain(<SecretReveal endpoint="/vault/credentials/7/reveal/" field="password" label="Password" {...props} />)
  return api
}

describe('SecretReveal', () => {
  it('is masked by default and never calls the server until asked', () => {
    const api = setup()
    expect(screen.getByLabelText('Password (hidden)')).toBeInTheDocument()
    expect(screen.queryByTestId('revealed-secret')).toBeNull()
    expect(api.calls).toHaveLength(0)
  })

  it('reveals through an explicit POST and shows the value', async () => {
    const api = setup()
    await click('Reveal')
    expect(screen.getByTestId('revealed-secret')).toHaveTextContent(SECRET)
    expect(api.find('POST', URL_)).toHaveLength(1)
  })

  it('hides again after 30 seconds', async () => {
    vi.useFakeTimers()
    setup()
    await click('Reveal')
    expect(screen.getByTestId('revealed-secret')).toBeInTheDocument()
    await act(async () => {
      await vi.advanceTimersByTimeAsync(AUTO_HIDE_MS - 1)
    })
    expect(screen.getByTestId('revealed-secret')).toBeInTheDocument()
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2)
    })
    expect(screen.queryByTestId('revealed-secret')).toBeNull()
    expect(screen.queryByText(SECRET)).toBeNull()
  })

  it('can be hidden by hand and re-revealed (a new authorized request each time)', async () => {
    const api = setup()
    await click('Reveal')
    await click('Hide')
    expect(screen.queryByTestId('revealed-secret')).toBeNull()
    await click('Reveal')
    expect(api.find('POST', URL_)).toHaveLength(2)
  })

  it('hides when the tab is hidden', async () => {
    setup()
    await click('Reveal')
    Object.defineProperty(document, 'hidden', { value: true, configurable: true })
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'))
    })
    Object.defineProperty(document, 'hidden', { value: false, configurable: true })
    expect(screen.queryByTestId('revealed-secret')).toBeNull()
  })

  it('never writes the secret to browser storage, cookies or the URL', async () => {
    setup()
    await click('Reveal')
    const everything = JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }) + document.cookie + location.href
    expect(everything).not.toContain(SECRET)
  })

  it('copies on request and tells the user the clipboard clearing is best-effort', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { value: { writeText, readText: vi.fn() }, configurable: true })
    setup()
    await click('Reveal')
    await click('Copy')
    expect(writeText).toHaveBeenCalledWith(SECRET)
    expect(await screen.findByText(/best-effort/i)).toBeInTheDocument()
  })

  it('reports a blocked clipboard instead of failing silently', async () => {
    Object.defineProperty(navigator, 'clipboard', { value: { writeText: vi.fn().mockRejectedValue(new Error('x')), readText: vi.fn() }, configurable: true })
    setup()
    await click('Reveal')
    await click('Copy')
    expect(await screen.findByText(/blocked clipboard access/i)).toBeInTheDocument()
  })

  it.each([
    [410, 'grant_consumed', /already been used/i],
    [423, 'lockdown_active', /emergency lockdown/i],
    [403, 'grant_revoked', /revoked/i],
    [403, 'grant_expired', /expired/i],
    [403, 'device_trust_unavailable', /trusted device/i],
    [404, 'no_access', /not found/i],
  ])('shows a clear message for HTTP %i %s and reveals nothing', async (status, code, message) => {
    setup({}, fail(status, { detail: 'x', code }))
    await click('Reveal')
    expect(screen.getByRole('alert')).toHaveTextContent(message)
    expect(screen.queryByTestId('revealed-secret')).toBeNull()
  })

  describe('one-time (view-once) access', () => {
    it('asks for confirmation first and does not call the server until confirmed', async () => {
      const api = setup({ viewOnce: true }, { password: SECRET, via: 'grant', view_once: true, grant_id: 4 })
      await click('Reveal')
      expect(await screen.findByText(/can never be revealed again/i)).toBeInTheDocument()
      expect(api.calls).toHaveLength(0)
      await click('Cancel')
      expect(api.calls).toHaveLength(0)
    })

    it('after the one reveal the button is disabled so the UI cannot waste or retry the grant', async () => {
      const api = setup({ viewOnce: true }, { password: SECRET, via: 'grant', view_once: true, grant_id: 4 })
      await click('Reveal')
      await click('Reveal now')
      expect(screen.getByTestId('revealed-secret')).toHaveTextContent(SECRET)
      await click('Hide')
      expect(screen.getByRole('button', { name: 'Reveal' })).toBeDisabled()
      expect(screen.getByText(/one-time access has now been used/i)).toBeInTheDocument()
      expect(api.find('POST', URL_)).toHaveLength(1)
    })
  })

  it('renders multi-line secrets (secure notes) verbatim and as text, not HTML', async () => {
    mockApi({ 'POST /api/vault/notes/3/reveal/': { content: 'line1\n<img src=x onerror=alert(1)>', via: 'owner', view_once: false, grant_id: null } })
    renderPlain(<SecretReveal endpoint="/vault/notes/3/reveal/" field="content" label="Content" multiline />)
    await click('Reveal')
    const el = screen.getByTestId('revealed-secret')
    expect(el.textContent).toBe('line1\n<img src=x onerror=alert(1)>')
    expect(el.querySelector('img')).toBeNull()
  })
})
