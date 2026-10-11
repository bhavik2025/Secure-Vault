// Real-browser smoke test of the RUNNING app (development only).
//
// Prerequisites: Docker services up, backend on :8000, `npm run dev` on :5173, and demo data from
//   SECUREVAULT_DEMO_PASSWORD=<pw> python manage.py seed_demo
// Run:   SECUREVAULT_DEMO_PASSWORD=<pw> npm run e2e
// Optional env: E2E_BASE_URL, E2E_BROWSER_CHANNEL (msedge | chrome), E2E_SCREENSHOT_DIR, E2E_HEADED=1
//
// It drives an installed Edge/Chrome through playwright-core (no browser download) as several real users:
// create -> reveal -> one-time share -> delegation -> cascading revoke -> lockdown -> access request -> admin.
import { execFileSync } from 'node:child_process'
import { mkdirSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright-core'

const BASE = process.env.E2E_BASE_URL ?? 'http://localhost:5173'
const PASSWORD = process.env.SECUREVAULT_DEMO_PASSWORD
const SHOTS = process.env.E2E_SCREENSHOT_DIR
const CHANNEL = process.env.E2E_BROWSER_CHANNEL ?? 'msedge'
const here = path.dirname(fileURLToPath(import.meta.url))
const BACKEND = path.resolve(here, '../../backend')
const PYTHON = process.env.E2E_PYTHON ?? path.join(BACKEND, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python')

if (!PASSWORD) {
  console.error('Set SECUREVAULT_DEMO_PASSWORD to the password you used with `manage.py seed_demo`.')
  process.exit(2)
}
if (SHOTS) mkdirSync(SHOTS, { recursive: true })

let n = 0
const passed = []
function assert(cond, message) {
  if (!cond) throw new Error(message)
}
async function step(name, fn) {
  n += 1
  const t0 = Date.now()
  try {
    await fn()
    passed.push(name)
    console.log(`  ok   ${String(n).padStart(2)} ${name} (${Date.now() - t0} ms)`)
  } catch (err) {
    console.error(`  FAIL ${String(n).padStart(2)} ${name}\n       ${String(err.message).split('\n').slice(0, 4).join('\n       ')}`)
    if (SHOTS) for (const [i, c] of sessions.entries()) for (const p of c.pages()) await p.screenshot({ path: path.join(SHOTS, `FAIL-${n}-${i}.png`) }).catch(() => {})
    throw err
  }
}
async function shot(page, name) {
  if (SHOTS) await page.screenshot({ path: path.join(SHOTS, `${String(n).padStart(2, '0')}-${name}.png`), fullPage: true })
}
function django(code) {
  return execFileSync(PYTHON, ['manage.py', 'shell', '-c', code], { cwd: BACKEND, encoding: 'utf8' })
}
const LOCK_ON = `
from apps.lockdown.models import LockdownState
from apps.organizations.models import Organization
from apps.accounts.models import User
LockdownState.objects.create(organization=Organization.objects.get(slug='demo'), scope='GLOBAL',
    initiator=User.objects.get(email='admin@demo.example'), reason='E2E drill')`
const LOCK_OFF = `
from django.utils import timezone
from apps.lockdown.models import LockdownState
LockdownState.objects.filter(organization__slug='demo', is_active=True).update(is_active=False, resolved_at=timezone.now())`

const browser = await chromium.launch({ channel: CHANNEL, headless: !process.env.E2E_HEADED })
const sessions = []

async function signIn(email, viewport = { width: 1280, height: 860 }) {
  const context = await browser.newContext({ baseURL: BASE, viewport })
  sessions.push(context) // registered first, so a failure still gets a screenshot and a clean close
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: BASE })
  const page = await context.newPage()
  page.setDefaultTimeout(20_000)
  await page.goto('/login')
  await page.getByLabel('Email').fill(email)
  await page.getByLabel('Password', { exact: true }).fill(PASSWORD)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await page.getByRole('button', { name: 'Sign out' }).waitFor() // visible at every screen size (the sidebar is not on phones)
  return page
}
const dialog = (page) => page.getByRole('dialog')
const title = `E2E credential ${new Date().toISOString().slice(0, 19).replace('T', ' ')}`
let password = ''
let credentialPath = ''
let requestCode = ''

let exitCode = 0
try {
  // ---------- Alice: owner ----------
  const alice = await signIn('alice@demo.example')

  await step('Alice signs in and sees her dashboard', async () => {
    await alice.getByRole('heading', { name: /welcome, alice engineer/i }).waitFor()
    await alice.getByText('Credentials in your vault').waitFor()
    await shot(alice, 'dashboard')
  })

  await step('Vault lists seeded credentials with hygiene badges', async () => {
    await alice.getByRole('link', { name: 'Vault', exact: true }).click()
    await alice.getByRole('link', { name: 'GitHub deploy bot' }).waitFor()
    await alice.getByRole('table', { name: 'Your credentials' }).getByText('Expiring soon').first().waitFor()
    await shot(alice, 'vault')
  })

  await step('Alice creates a credential with a server-generated password', async () => {
    await alice.getByRole('button', { name: 'New credential' }).click()
    const d = dialog(alice)
    await d.getByLabel('Title').fill(title)
    await d.getByLabel('Username').fill('e2e-user')
    await d.getByLabel('Service').selectOption({ label: 'GitHub' })
    await d.getByRole('button', { name: 'Generate' }).click()
    const field = d.getByLabel('Password', { exact: true })
    await alice.waitForFunction((el) => el.value.length >= 12, await field.elementHandle())
    password = await field.inputValue()
    await d.getByText(/bits of entropy/).waitFor()
    await shot(alice, 'create-credential')
    await d.getByRole('button', { name: 'Create credential' }).click()
    await alice.getByRole('heading', { level: 1, name: title }).waitFor()
    credentialPath = new URL(alice.url()).pathname
    assert(/^\/vault\/\d+$/.test(credentialPath), `unexpected URL ${credentialPath}`)
    requestCode = (await alice.locator('code').filter({ hasText: /^[0-9a-f]{8}-[0-9a-f]{4}-/ }).first().textContent()).trim()
    assert(requestCode.length === 36, 'owner should see the access request ID')
  })

  await step('The secret is masked; Reveal shows it; Copy puts it on the clipboard', async () => {
    await alice.getByLabel('Password (hidden)').waitFor()
    await alice.getByRole('button', { name: 'Reveal', exact: true }).click()
    const shown = (await alice.getByTestId('revealed-secret').textContent()).trim()
    assert(shown === password, 'revealed secret does not match the generated password')
    await alice.getByRole('button', { name: 'Copy', exact: true }).first().click()
    await alice.getByText(/best-effort/).waitFor()
    assert((await alice.evaluate(() => navigator.clipboard.readText())) === password, 'clipboard does not hold the secret')
    await alice.getByRole('button', { name: 'Hide', exact: true }).click()
    await alice.getByLabel('Password (hidden)').waitFor()
    const stored = await alice.evaluate(() => JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }) + document.cookie)
    assert(!stored.includes(password), 'secret leaked into browser storage')
    await shot(alice, 'credential-detail')
  })

  await step('Alice shares it with Bob as a one-time view', async () => {
    await alice.getByRole('button', { name: 'Share', exact: true }).click()
    const d = dialog(alice)
    await d.getByLabel("Colleague's email").fill('bob@demo.example')
    await d.getByLabel(/one-time view/i).check()
    assert(await d.getByLabel(/edit the credential/i).isDisabled(), 'one-time view must lock other permissions')
    await shot(alice, 'share-dialog')
    await d.getByRole('button', { name: 'Share', exact: true }).click()
    await alice.getByText('Shared with bob@demo.example.').waitFor()
    await alice.getByRole('table', { name: 'Shares of this credential' }).getByText('One-time').waitFor()
  })

  // ---------- Bob: recipient ----------
  const bob = await signIn('bob@demo.example')

  await step('Bob is notified and finds the credential under Shared with me', async () => {
    await bob.getByLabel(/\d+ unread/).waitFor()
    await bob.getByRole('link', { name: 'Shared', exact: true }).click()
    await bob.getByRole('link', { name: title }).click()
    await bob.getByText('One-time view').first().waitFor()
  })

  await step('Bob reveals it exactly once after confirming', async () => {
    await bob.getByRole('button', { name: 'Reveal', exact: true }).click()
    await bob.getByText(/can never be revealed again/).waitFor()
    await bob.getByRole('button', { name: 'Reveal now' }).click()
    assert((await bob.getByTestId('revealed-secret').textContent()).trim() === password, 'Bob saw the wrong secret')
    await bob.getByRole('button', { name: 'Hide', exact: true }).click()
    assert(await bob.getByRole('button', { name: 'Reveal', exact: true }).isDisabled(), 'Reveal should be disabled after use')
  })

  await step('The one-time access is gone on reload (HTTP 410 from the server)', async () => {
    await bob.reload()
    await bob.getByRole('alert').filter({ hasText: /already been used/ }).waitFor()
    await shot(bob, 'view-once-consumed')
  })

  // ---------- delegation and cascading revocation ----------
  await step('Alice gives Bob view+share; Bob delegates to the manager', async () => {
    await alice.reload()
    await alice.getByRole('button', { name: 'Share', exact: true }).click()
    const d = dialog(alice)
    await d.getByLabel("Colleague's email").fill('bob@demo.example')
    await d.getByLabel(/share it onward/i).check()
    await d.getByRole('button', { name: 'Share', exact: true }).click()
    await alice.getByText('Shared with bob@demo.example.').waitFor()

    await bob.goto(credentialPath)
    await bob.getByText('Access you have delegated').waitFor()
    await bob.getByRole('button', { name: 'Delegate' }).click()
    const bd = dialog(bob)
    assert(await bd.getByLabel(/edit the credential/i).isDisabled(), 'Bob cannot hand on EDIT he does not hold')
    await bd.getByLabel("Colleague's email").fill('manager@demo.example')
    await bd.getByRole('button', { name: 'Share', exact: true }).click()
    await bob.getByText('Shared with manager@demo.example.').waitFor()
  })

  const manager = await signIn('manager@demo.example')

  await step('The manager can reveal through the delegated grant', async () => {
    await manager.goto(credentialPath)
    await manager.getByRole('button', { name: 'Reveal', exact: true }).click()
    assert((await manager.getByTestId('revealed-secret').textContent()).trim() === password, 'manager saw the wrong secret')
  })

  await step("Revoking Bob's grant cascades to the manager", async () => {
    await alice.reload()
    await alice.getByRole('button', { name: 'Delegation tree' }).click()
    await alice.getByRole('list', { name: 'Delegation tree' }).getByText('manager@demo.example').waitFor()
    await shot(alice, 'delegation-tree')
    await alice.getByRole('button', { name: 'Show list' }).click()
    await alice.getByRole('button', { name: 'Revoke access for bob@demo.example' }).click()
    await dialog(alice).getByText(/passed this access on to will lose it too/).waitFor()
    await dialog(alice).getByRole('button', { name: 'Revoke' }).click()
    await alice.getByText(/revoked for 2 people/).waitFor()
    await manager.reload()
    await manager.getByRole('alert').filter({ hasText: /revoked/ }).waitFor()
  })

  // ---------- emergency lockdown ----------
  await step('An active lockdown blocks reveal server-side; lifting it restores access', async () => {
    await alice.reload()
    django(LOCK_ON)
    try {
      await alice.getByRole('button', { name: 'Reveal', exact: true }).click()
      await alice.getByText('Emergency lockdown is active.', { exact: true }).waitFor()
      await alice.getByRole('alert').filter({ hasText: /blocked until it is lifted/ }).first().waitFor()
      assert((await alice.getByTestId('revealed-secret').count()) === 0, 'secret shown during lockdown')
      await shot(alice, 'lockdown')
    } finally {
      django(LOCK_OFF)
    }
    await alice.getByRole('button', { name: 'Dismiss' }).click()
    await alice.getByRole('button', { name: 'Reveal', exact: true }).click()
    assert((await alice.getByTestId('revealed-secret').textContent()).trim() === password, 'reveal failed after lockdown')
  })

  // ---------- access request ----------
  await step('Bob requests access with the request ID; Alice approves; Bob can reveal', async () => {
    await bob.goto('/requests')
    await bob.getByRole('button', { name: 'Request access' }).click()
    const d = dialog(bob)
    await d.getByLabel('Credential ID').fill(requestCode)
    await d.getByLabel(/why do you need access/i).fill('Need to rotate the deploy key during the release')
    await d.getByLabel(/how many hours/i).fill('2')
    await d.getByRole('button', { name: 'Send request' }).click()
    await bob.getByText('Request sent. The owner has been notified.').waitFor()
    await bob.getByRole('table').getByText('PENDING').waitFor()

    await alice.goto('/requests')
    await alice.getByRole('tab', { name: 'To review' }).click()
    await alice.getByRole('button', { name: 'Approve request from bob@demo.example' }).click()
    await shot(alice, 'approve-request')
    await dialog(alice).getByRole('button', { name: 'Approve' }).click()
    await alice.getByText('Request approved.').waitFor()

    await bob.goto(credentialPath)
    await bob.getByRole('button', { name: 'Reveal', exact: true }).click()
    assert((await bob.getByTestId('revealed-secret').textContent()).trim() === password, 'approved access did not work')
  })

  // ---------- administration and permissions ----------
  await step('An employee cannot open admin pages', async () => {
    await alice.goto('/admin/audit')
    await alice.getByRole('alert').filter({ hasText: /do not have permission/ }).waitFor()
  })

  const admin = await signIn('admin@demo.example')

  await step('The administrator sees employees, the active policy and the audit trail', async () => {
    await admin.getByRole('link', { name: 'Employees' }).click()
    await admin.getByRole('cell', { name: 'alice@demo.example', exact: true }).waitFor()
    await admin.getByRole('link', { name: 'Security policies' }).click()
    await admin.getByText('Active: Default Policy').waitFor()
    await admin.getByRole('link', { name: 'Audit log' }).click()
    await admin.getByLabel('Action').selectOption('REVEAL')
    const table = admin.getByRole('table', { name: /audit events/i })
    await table.getByText('granted_view_once').first().waitFor() // Bob's single one-time reveal
    await table.getByText('lockdown_active').first().waitFor()
    await shot(admin, 'audit-log')
  })

  await step('The layout works on a phone-sized screen', async () => {
    const phone = await signIn('alice@demo.example', { width: 390, height: 844 })
    await phone.getByRole('button', { name: 'Toggle navigation' }).click()
    await phone.getByRole('link', { name: 'Vault', exact: true }).click()
    await phone.getByRole('link', { name: 'GitHub deploy bot' }).waitFor()
    const overflow = await phone.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1)
    await shot(phone, 'mobile-vault')
    assert(!overflow, 'page scrolls horizontally on a phone-sized screen')
  })

  await step('Alice archives the test credential (it disappears from the vault, the secret is locked)', async () => {
    await alice.goto(credentialPath)
    await alice.getByRole('button', { name: 'Archive' }).click()
    await dialog(alice).getByText(/can no longer be revealed/).waitFor()
    await dialog(alice).getByRole('button', { name: 'Archive' }).click()
    await alice.getByText('Credential archived.').waitFor()
    await alice.getByText(/restore this credential to reveal/i).waitFor()
    await alice.goto('/vault')
    await alice.getByRole('link', { name: 'GitHub deploy bot' }).waitFor()
    assert((await alice.getByRole('link', { name: title }).count()) === 0, 'archived credential still listed')
  })

  await step('Signing out ends the session', async () => {
    await alice.getByRole('button', { name: 'Sign out' }).click()
    await alice.getByRole('heading', { name: /sign in to securevault/i }).waitFor()
    await alice.goto(credentialPath)
    await alice.getByRole('heading', { name: /sign in to securevault/i }).waitFor()
  })
} catch {
  exitCode = 1
} finally {
  for (const c of sessions) await c.close().catch(() => {})
  await browser.close()
}
console.log(`\n${passed.length} step(s) passed${exitCode ? ', then a step FAILED' : ''}.`)
process.exit(exitCode)
