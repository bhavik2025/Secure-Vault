import { render, screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import App from './App'

afterEach(() => vi.restoreAllMocks())

it('shows service status from the health endpoint', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    new Response(JSON.stringify({ status: 'ok', database: true, redis: false }), { status: 200 }),
  )
  render(<App />)
  expect(await screen.findByLabelText('PostgreSQL connected')).toBeInTheDocument()
  expect(screen.getByLabelText('Redis unreachable')).toBeInTheDocument()
})

it('shows an error when the API is unreachable', async () => {
  vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('network'))
  render(<App />)
  expect(await screen.findByRole('alert')).toHaveTextContent('Cannot reach the SecureVault API.')
})
