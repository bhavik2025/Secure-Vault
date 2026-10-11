import { useState, type FormEvent } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'
import { Button, FormError, TextField } from '../components/ui'
import { ApiError } from '../lib/api'
import { errorMessage } from '../lib/errors'

export function LoginPage() {
  const { status, login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const from = (location.state as { from?: string } | null)?.from ?? '/'
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string>()
  const [busy, setBusy] = useState(false)

  if (status === 'authenticated') return <Navigate to={from} replace />

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError(undefined)
    setBusy(true)
    try {
      await login(email.trim(), password)
      navigate(from, { replace: true })
    } catch (err) {
      // The server deliberately gives one message for every failure cause; we do the same.
      setError(err instanceof ApiError && err.status === 401 ? 'Invalid email or password.' : errorMessage(err))
      setPassword('')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <form
        onSubmit={(e) => void submit(e)}
        className="w-full max-w-sm space-y-5 rounded-2xl bg-white p-8 shadow-lg ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800"
        aria-labelledby="login-title"
      >
        <div>
          <h1 id="login-title" className="text-2xl font-semibold text-slate-900 dark:text-slate-100">
            Sign in to SecureVault
          </h1>
          <p className="mt-1 text-sm text-slate-500">Zero-trust credential and access management</p>
        </div>
        <FormError message={error} />
        <TextField
          label="Email"
          type="email"
          autoComplete="username"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <TextField
          label="Password"
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <Button type="submit" loading={busy} className="w-full">
          Sign in
        </Button>
        <p className="text-xs text-slate-500">
          Accounts are created by your administrator. Sessions end after 30 minutes of inactivity.
        </p>
      </form>
    </div>
  )
}
