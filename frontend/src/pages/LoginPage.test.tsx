import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { afterEach, expect, it, vi } from 'vitest'
import { fail, me, mockApi, renderApp } from '../test/utils'
import { LoginPage } from './LoginPage'

afterEach(() => vi.restoreAllMocks())

const tree = (
  <Routes>
    <Route path="/login" element={<LoginPage />} />
    <Route path="/" element={<p>HOME</p>} />
    <Route path="/vault" element={<p>VAULT PAGE</p>} />
  </Routes>
)

it('primes CSRF, then logs in with the typed credentials and lands on the page the user wanted', async () => {
  const api = mockApi({
    'GET /api/auth/me/': fail(403, { detail: 'x', code: 'not_authenticated' }),
    'GET /api/auth/csrf/': { detail: 'CSRF cookie set' },
    'POST /api/auth/login/': me(),
  })
  renderApp(tree, { route: '/login' })
  const user = userEvent.setup()
  await user.type(await screen.findByLabelText('Email'), '  ada@acme.example ')
  await user.type(screen.getByLabelText('Password'), 'Correct-Horse-9!')
  await user.click(screen.getByRole('button', { name: 'Sign in' }))
  expect(await screen.findByText('HOME')).toBeInTheDocument()

  const order = api.calls.filter((c) => c.path !== '/api/auth/me/').map((c) => `${c.method} ${c.path}`)
  expect(order).toEqual(['GET /api/auth/csrf/', 'POST /api/auth/login/'])
  expect(api.find('POST', '/api/auth/login/')[0].body).toEqual({ email: 'ada@acme.example', password: 'Correct-Horse-9!' })
})

it('shows one generic message for a failed login and clears the password field', async () => {
  mockApi({
    'GET /api/auth/me/': fail(403, { detail: 'x', code: 'not_authenticated' }),
    'GET /api/auth/csrf/': { detail: 'ok' },
    'POST /api/auth/login/': fail(401, { detail: 'Invalid email or password.' }),
  })
  renderApp(tree, { route: '/login' })
  const user = userEvent.setup()
  await user.type(await screen.findByLabelText('Email'), 'ada@acme.example')
  await user.type(screen.getByLabelText('Password'), 'wrong')
  await user.click(screen.getByRole('button', { name: 'Sign in' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Invalid email or password.')
  expect(screen.getByLabelText('Password')).toHaveValue('')
  expect(screen.queryByText('HOME')).toBeNull()
})

it('reports throttling and network problems distinctly from bad credentials', async () => {
  mockApi({
    'GET /api/auth/me/': fail(403, { detail: 'x', code: 'not_authenticated' }),
    'GET /api/auth/csrf/': { detail: 'ok' },
    'POST /api/auth/login/': fail(429, { detail: 'Request was throttled.' }),
  })
  renderApp(tree, { route: '/login' })
  const user = userEvent.setup()
  await user.type(await screen.findByLabelText('Email'), 'a@b.co')
  await user.type(screen.getByLabelText('Password'), 'x')
  await user.click(screen.getByRole('button', { name: 'Sign in' }))
  expect(await screen.findByRole('alert')).toHaveTextContent(/too many requests/i)
})

it('redirects an already signed-in user away from the login page', async () => {
  mockApi({ 'GET /api/auth/me/': me() })
  renderApp(tree, { route: '/login' })
  await waitFor(() => expect(screen.getByText('HOME')).toBeInTheDocument())
})

it('never keeps the password anywhere after submitting', async () => {
  mockApi({
    'GET /api/auth/me/': fail(403, { detail: 'x', code: 'not_authenticated' }),
    'GET /api/auth/csrf/': { detail: 'ok' },
    'POST /api/auth/login/': me(),
  })
  renderApp(tree, { route: '/login' })
  const user = userEvent.setup()
  await user.type(await screen.findByLabelText('Email'), 'ada@acme.example')
  await user.type(screen.getByLabelText('Password'), 'Sup3r-Secret-Pw!')
  await user.click(screen.getByRole('button', { name: 'Sign in' }))
  await screen.findByText('HOME')
  expect(JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }) + document.cookie).not.toContain('Sup3r-Secret-Pw!')
})
