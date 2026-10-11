# SecureVault frontend

React 19 + TypeScript + Vite + Tailwind 4. It talks only to the Django API (`docs/api.md`); every security
decision is made by the server. The UI hides what you cannot do, but that is a convenience, never a control.

## How it connects to the backend
- **Same origin.** The browser only talks to the SPA's origin. In development Vite proxies `/api` and `/ws` to
  Django on `127.0.0.1:8000`; in production a reverse proxy does the same. Session and CSRF cookies therefore
  never need cross-site settings.
- **Session cookie auth.** `HttpOnly` session cookie; the SPA never sees or stores it.
- **CSRF.** `GET /api/auth/csrf/` sets `csrftoken`; every unsafe request echoes it in `X-CSRFToken`
  (`src/lib/api.ts`). Login primes the cookie first.
- **Errors.** The API returns `{detail, code}`; `src/lib/errors.ts` turns codes such as `grant_consumed`,
  `lockdown_active`, `exceeds_upstream_lifetime` into plain-language messages, and DRF field errors are shown
  next to the matching form fields.
- **Global signals.** Any `423 lockdown_active` raises a red lockdown banner; any `403 not_authenticated`
  (session expired, account suspended) returns the user to the sign-in page.

## Screens
| Route | Who | What |
|---|---|---|
| `/login` | everyone | Sign in (one generic error for every failure, like the server) |
| `/` | signed in | Dashboard: counts, expiring/expired, pending reviews, notifications, active policy |
| `/vault`, `/vault/:id` | `vault.use` | Credentials: search, filters, sort, pagination; detail with masked secret, reveal, edit, archive, sharing |
| `/notes` | `vault.use` | Encrypted secure notes, owner-only reveal |
| `/shared` | `vault.use` | Shared with me / shared by me (with revoke) |
| `/requests` | `vault.use` | Request access by request ID; approve/reject (owner or same-department manager) |
| `/notifications` | signed in | In-app notifications, mark read |
| `/admin/departments` | `departments.view` (`.manage` to edit) | Departments |
| `/admin/employees` | `users.view` (`users.manage` for status) | Account status changes with reason |
| `/admin/services` | `services.view` (`.manage` to edit) | Service catalog (deactivate, never delete) |
| `/admin/policies` | `policies.view` (`.manage` to edit) | Security policies, activate one |
| `/admin/audit` | `audit.view` | Audit trail with action/outcome filters |
| `/profile` | signed in | Account, roles, permissions, session rules |

Typing an admin URL without the permission shows a permission screen and makes **no** API call; if it did call,
the server would refuse anyway.

## Secret-handling rules (implemented in `SecretReveal`)
1. **Masked by default.** Lists, details and every non-reveal response contain only a fixed-width mask.
2. **Reveal is an explicit `POST`**, never `GET` (no prefetching, no caching), and runs the full server pipeline
   (permission/grant, expiry, device policy, lockdown, audit).
3. **Plaintext lives only in component state**: never in `localStorage`/`sessionStorage`/IndexedDB, the URL or a
   cache. Tests assert this.
4. **Auto-hide** after 30 seconds, when the tab is hidden, and on navigation away.
5. **Clipboard**: "Copy" clears the clipboard after 30 seconds **best-effort** (only if it still holds the secret,
   or if the browser will not let us check). Browsers may block this; the UI says so.
6. **One-time (view-once) grants** ask for confirmation first, and the button is disabled after the single use.
7. Secrets and notes are rendered as text (never HTML), so stored content cannot inject markup.

## Testing
- **Unit and component tests** (Vitest + Testing Library, jsdom): `npm test`. The fetch layer is mocked by route
  (`src/test/utils.tsx`).
- **Real-browser smoke test** (`e2e/smoke.mjs`, playwright-core driving an installed Edge or Chrome, so no browser
  download): signs in as five demo users and walks through create, reveal, copy, one-time sharing, delegation,
  cascading revocation, lockdown, access request and approval, admin pages, a phone-sized layout, archive and sign-out.

```powershell
# terminal 1 (backend):  cd backend
$env:SECUREVAULT_DEMO_PASSWORD = "Choose-a-Dev-Passw0rd!"
.\.venv\Scripts\python.exe manage.py seed_demo
.\.venv\Scripts\python.exe manage.py runserver 127.0.0.1:8000
# terminal 2 (frontend): cd frontend ; npm run dev
# terminal 3 (frontend): same password as above
$env:SECUREVAULT_DEMO_PASSWORD = "Choose-a-Dev-Passw0rd!"
npm run e2e    # optional: $env:E2E_SCREENSHOT_DIR = "C:\temp\sv-shots"; $env:E2E_BROWSER_CHANNEL = "chrome"
```
The smoke test briefly creates and lifts a lockdown in the demo organization (via `manage.py shell`) and archives
the credential it creates.

## Known limits
- Real-time updates (WebSocket) are not wired yet; the notification badge refreshes every 60 seconds.
- No invitation/onboarding or password-change screens yet (those backend modules are not built). Use
  `bootstrap_org` for a real organization and `seed_demo` for development data.
- Device registration, emergency-lockdown controls, reports and import screens arrive with their backend modules.
