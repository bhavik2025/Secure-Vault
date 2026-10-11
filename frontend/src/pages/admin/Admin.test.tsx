import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import type { Employee, SecurityPolicy, ServiceEntry } from '../../lib/types'
import { ADMIN_PERMS, fail, me, mockApi, page, renderApp } from '../../test/utils'
import { AuditPage } from './AuditPage'
import { DepartmentsPage } from './DepartmentsPage'
import { EmployeesPage } from './EmployeesPage'
import { PoliciesPage } from './PoliciesPage'
import { ServicesPage } from './ServicesPage'

afterEach(() => vi.restoreAllMocks())
const ADMIN = me({ id: 1, roles: ['PLATFORM_ADMIN'], permissions: ADMIN_PERMS })
const employee = (over: Partial<Employee> = {}): Employee => ({ id: 2, email: 'bob@acme.example', full_name: 'Bob', department: null, status: 'ACTIVE', roles: ['EMPLOYEE'], last_login: null, ...over })
const policy = (over: Partial<SecurityPolicy> = {}): SecurityPolicy => ({
  id: 1, name: 'Default Policy', min_length: 12, require_symbols: true, max_age_days: 90, allow_view_once: true, require_device_trust: false,
  is_active: true, created_at: '', updated_at: '', ...over,
})
const service = (over: Partial<ServiceEntry> = {}): ServiceEntry => ({
  id: 3, name: 'AWS', category: 'CLOUD', base_url: 'https://aws.amazon.com', icon_url: '', default_port: null, status: 'ACTIVE', created_at: '', updated_at: '', ...over,
})

// ---- employees -------------------------------------------------------------------------------------------

it('employees: status change requires a reason, warns that sessions end, and cannot target yourself or deactivated users', async () => {
  const api = mockApi({
    'GET /api/auth/me/': ADMIN,
    'GET /api/org/employees/': page([employee(), employee({ id: 1, email: 'ada@acme.example' }), employee({ id: 3, email: 'gone@acme.example', status: 'DEACTIVATED' })]),
    'POST /api/org/employees/2/status/': employee({ status: 'SUSPENDED' }),
  })
  renderApp(<EmployeesPage />)
  await screen.findByText('bob@acme.example')
  expect(screen.getAllByRole('button', { name: /change status/i })).toHaveLength(1) // not self, not deactivated
  await userEvent.click(screen.getByRole('button', { name: /change status of bob@acme.example/i }))
  const dialog = await screen.findByRole('dialog')
  expect(within(dialog).getByText(/active sessions end immediately/i)).toBeInTheDocument()
  expect(within(dialog).getByRole('textbox', { name: 'Reason' })).toBeRequired()
  await userEvent.type(within(dialog).getByRole('textbox', { name: 'Reason' }), 'Investigation')
  await userEvent.click(within(dialog).getByRole('button', { name: 'Confirm' }))
  await waitFor(() => expect(api.find('POST', '/api/org/employees/2/status/')).toHaveLength(1))
  expect(api.find('POST', '/api/org/employees/2/status/')[0].body).toEqual({ status: 'SUSPENDED', reason: 'Investigation' })
})

it('employees: users without users.manage see the list but no action buttons', async () => {
  mockApi({
    'GET /api/auth/me/': me({ permissions: ['users.view'] }),
    'GET /api/org/employees/': page([employee()]),
  })
  renderApp(<EmployeesPage />)
  await screen.findByText('bob@acme.example')
  expect(screen.queryByRole('button', { name: /change status/i })).toBeNull()
})

// ---- policies --------------------------------------------------------------------------------------------

it('policies: shows the active policy and creates a new one with "never expires" as null', async () => {
  const api = mockApi({
    'GET /api/auth/me/': ADMIN,
    'GET /api/org/security-policies/': page([policy()]),
    'POST /api/org/security-policies/': policy({ id: 2, is_active: false }),
  })
  renderApp(<PoliciesPage />)
  expect(await screen.findByText('Active: Default Policy')).toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'New policy' }))
  const dialog = await screen.findByRole('dialog')
  const user = userEvent.setup()
  await user.type(within(dialog).getByLabelText('Policy name'), 'Relaxed')
  await user.clear(within(dialog).getByLabelText('Minimum password length'))
  await user.type(within(dialog).getByLabelText('Minimum password length'), '10')
  await user.click(within(dialog).getByLabelText(/never expire/i))
  expect(within(dialog).queryByLabelText(/maximum credential age/i)).toBeNull()
  await user.click(within(dialog).getByLabelText(/allow one-time/i))
  await user.click(within(dialog).getByRole('button', { name: 'Create' }))
  await waitFor(() => expect(api.find('POST', '/api/org/security-policies/')).toHaveLength(1))
  expect(api.find('POST', '/api/org/security-policies/')[0].body).toEqual({
    name: 'Relaxed', min_length: 10, require_symbols: true, max_age_days: null, allow_view_once: false, require_device_trust: false,
  })
})

it('policies: warns that device trust currently blocks reveals, and activation is explicit', async () => {
  const api = mockApi({
    'GET /api/auth/me/': ADMIN,
    'GET /api/org/security-policies/': page([policy(), policy({ id: 2, name: 'Strict', is_active: false, min_length: 20 })]),
    'POST /api/org/security-policies/2/activate/': policy({ id: 2, is_active: true }),
  })
  renderApp(<PoliciesPage />)
  await screen.findByText('Strict')
  await userEvent.click(screen.getByRole('button', { name: 'Activate Strict' }))
  await waitFor(() => expect(api.find('POST', '/api/org/security-policies/2/activate/')).toHaveLength(1))
  await userEvent.click(screen.getByRole('button', { name: 'New policy' }))
  expect(await screen.findByText(/currently blocks secret reveal for everyone/i)).toBeInTheDocument()
})

it('policies: security admins can read but not change', async () => {
  mockApi({ 'GET /api/auth/me/': me({ permissions: ['policies.view'] }), 'GET /api/org/security-policies/': page([policy()]) })
  renderApp(<PoliciesPage />)
  await screen.findByText('Active: Default Policy')
  expect(screen.queryByRole('button', { name: 'New policy' })).toBeNull()
  expect(screen.queryByRole('button', { name: /edit/i })).toBeNull()
})

// ---- services ---------------------------------------------------------------------------------------------

it('services: creates a service and shows server-side URL validation next to the field', async () => {
  const api = mockApi({
    'GET /api/auth/me/': ADMIN,
    'GET /api/org/services/': page([service()]),
    'POST /api/org/services/': fail(400, { base_url: ['URL must not contain embedded credentials.'] }),
  })
  renderApp(<ServicesPage />)
  await userEvent.click(await screen.findByRole('button', { name: 'New service' }))
  const dialog = await screen.findByRole('dialog')
  const user = userEvent.setup()
  await user.type(within(dialog).getByLabelText('Name'), 'Bad')
  await user.type(within(dialog).getByLabelText('Base URL'), 'https://u:p@host.example.com')
  await user.click(within(dialog).getByRole('button', { name: 'Create' }))
  expect(await within(dialog).findByText(/embedded credentials/i)).toBeInTheDocument()
  expect(api.find('POST', '/api/org/services/')[0].body).toMatchObject({ name: 'Bad', default_port: null })
})

it('services: deactivate (never delete) and non-managers get a read-only catalog', async () => {
  const api = mockApi({
    'GET /api/auth/me/': ADMIN,
    'GET /api/org/services/': page([service()]),
    'POST /api/org/services/3/deactivate/': service({ status: 'INACTIVE' }),
  })
  renderApp(<ServicesPage />)
  await userEvent.click(await screen.findByRole('button', { name: 'Deactivate AWS' }))
  await waitFor(() => expect(api.find('POST', '/api/org/services/3/deactivate/')).toHaveLength(1))
  expect(screen.queryByRole('button', { name: /delete/i })).toBeNull()
})

it('services: employees see the catalog without management buttons', async () => {
  mockApi({ 'GET /api/auth/me/': me(), 'GET /api/org/services/': page([service()]) })
  renderApp(<ServicesPage />)
  await screen.findByText('AWS')
  expect(screen.queryByRole('button', { name: 'New service' })).toBeNull()
  expect(screen.queryByRole('button', { name: /deactivate/i })).toBeNull()
})

// ---- departments & audit ------------------------------------------------------------------------------------

it('departments: creates with an upper-cased code and an optional head', async () => {
  const api = mockApi({
    'GET /api/auth/me/': ADMIN,
    'GET /api/org/departments/': page([]),
    'GET /api/org/employees/': page([employee()]),
    'POST /api/org/departments/': { id: 1 },
  })
  renderApp(<DepartmentsPage />)
  await userEvent.click(await screen.findByRole('button', { name: 'New department' }))
  const dialog = await screen.findByRole('dialog')
  const user = userEvent.setup()
  await user.type(within(dialog).getByLabelText('Name'), 'Engineering')
  await user.type(within(dialog).getByLabelText('Code'), 'eng')
  await user.selectOptions(within(dialog).getByLabelText('Department head'), '2')
  await user.click(within(dialog).getByRole('button', { name: 'Create' }))
  await waitFor(() => expect(api.find('POST', '/api/org/departments/')).toHaveLength(1))
  expect(api.find('POST', '/api/org/departments/')[0].body).toEqual({ name: 'Engineering', code: 'ENG', head: 2, status: 'ACTIVE' })
})

it('audit: lists events and passes filters to the server', async () => {
  const api = mockApi({
    'GET /api/auth/me/': ADMIN,
    'GET /api/audit/events/': page([
      { id: 1, created_at: '2026-01-01T10:00:00Z', actor_email: 'ada@acme.example', action: 'REVEAL', outcome: 'DENIED', target_type: 'credential', target_id: '4', reason_code: 'grant_consumed', ip_address: '127.0.0.1', request_id: 'x' },
    ]),
  })
  renderApp(<AuditPage />)
  expect(await screen.findByText('grant_consumed')).toBeInTheDocument()
  expect(screen.getByText('credential #4')).toBeInTheDocument()
  await userEvent.selectOptions(screen.getByLabelText('Action'), 'REVEAL')
  await userEvent.selectOptions(screen.getByLabelText('Outcome'), 'DENIED')
  await waitFor(() => expect(api.find('GET', '/api/audit/events/').at(-1)!.query).toMatchObject({ action: 'REVEAL', outcome: 'DENIED', page: '1' }))
})
