import { Link, Route, Routes } from 'react-router-dom'
import { RequireAuth, RequirePermission } from './auth/guards'
import { Layout } from './components/Layout'
import { CredentialDetailPage } from './pages/CredentialDetailPage'
import { DashboardPage } from './pages/DashboardPage'
import { LoginPage } from './pages/LoginPage'
import { NotesPage } from './pages/NotesPage'
import { NotificationsPage } from './pages/NotificationsPage'
import { ProfilePage } from './pages/ProfilePage'
import { RequestsPage } from './pages/RequestsPage'
import { SharedPage } from './pages/SharedPage'
import { VaultPage } from './pages/VaultPage'
import { AuditPage } from './pages/admin/AuditPage'
import { DepartmentsPage } from './pages/admin/DepartmentsPage'
import { EmployeesPage } from './pages/admin/EmployeesPage'
import { PoliciesPage } from './pages/admin/PoliciesPage'
import { ServicesPage } from './pages/admin/ServicesPage'

function NotFound() {
  return (
    <div className="py-16 text-center">
      <h1 className="text-2xl font-semibold">Page not found</h1>
      <p className="mt-2 text-sm text-slate-500">
        <Link to="/" className="text-indigo-600 hover:underline">
          Go to the dashboard
        </Link>
      </p>
    </div>
  )
}

const guard = (permission: string, element: React.ReactNode) => (
  <RequirePermission permission={permission}>{element}</RequirePermission>
)

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route index element={<DashboardPage />} />
        <Route path="vault" element={<VaultPage />} />
        <Route path="vault/:id" element={<CredentialDetailPage />} />
        <Route path="notes" element={<NotesPage />} />
        <Route path="shared" element={<SharedPage />} />
        <Route path="requests" element={<RequestsPage />} />
        <Route path="notifications" element={<NotificationsPage />} />
        <Route path="profile" element={<ProfilePage />} />
        <Route path="admin/departments" element={guard('departments.view', <DepartmentsPage />)} />
        <Route path="admin/employees" element={guard('users.view', <EmployeesPage />)} />
        <Route path="admin/services" element={guard('services.view', <ServicesPage />)} />
        <Route path="admin/policies" element={guard('policies.view', <PoliciesPage />)} />
        <Route path="admin/audit" element={guard('audit.view', <AuditPage />)} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  )
}
