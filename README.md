# SecureVault

Zero-trust enterprise credential & access management platform (educational MVP).

> **Crypto model:** server-side envelope encryption (AES-256-GCM, a fresh data key per secret wrapped by a
> versioned key-encryption key, separate HMAC blind-index key). SecureVault is **not** a zero-knowledge system:
> the server can decrypt when policy allows. See [docs/crypto.md](docs/crypto.md).

## What works today
- Sign-in with session cookies + CSRF, roles and permissions (RBAC), organization isolation, account status
- Encrypted credential vault and secure notes, password generator and strength estimate, policy enforcement
- Sharing with VIEW/EDIT/SHARE, delegation trees, cascading revocation, one-time (view-once) access, access requests
- Zero-trust reveal pipeline with server-side lockdown and device-policy gates, append-only hash-chained audit log
- Service catalog, security policies, departments, notifications
- A complete web UI for all of the above ([docs/frontend.md](docs/frontend.md))

Not built yet: invitations/Excel onboarding, device registration, lockdown controls + real-time push, reports.

## Layout
```
backend/    Django 5.2 + DRF + Channels (config/ = settings & ASGI, apps/ = domain apps)
frontend/   React 19 + TypeScript + Vite + Tailwind 4 (Vitest; e2e/ = real-browser smoke test)
docs/       api.md, crypto.md, sharing.md, frontend.md
docker-compose.yml   PostgreSQL 16 (host port 5433) + Redis 7 (host port 6379), loopback only
.env.example         placeholders only; copy to .env
```

## First-time setup (Windows PowerShell)
```powershell
# 1. Secrets/config
Copy-Item .env.example .env
# edit .env: DJANGO_SECRET_KEY, POSTGRES_PASSWORD and AUDIT_HMAC_KEY (generator command is in the file)

# 2. Services (Docker Desktop must be running)
docker compose up -d
docker compose ps            # both should be "healthy"

# 3. Backend
python -m venv backend\.venv
backend\.venv\Scripts\python.exe -m pip install -r backend\requirements-dev.txt
cd backend
.\.venv\Scripts\python.exe manage.py generate_vault_keys   # paste the 3 lines into .env (keep them secret)
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py check                 # must report no issues

# 4a. A real organization and its first administrator (asks for a password)
.\.venv\Scripts\python.exe manage.py bootstrap_org --name "Acme" --slug acme --admin-email you@acme.example --admin-name "Your Name"
# 4b. ...and/or development demo data: "Demo Corp" with one user per role (DEBUG only)
.\.venv\Scripts\python.exe manage.py seed_demo                # prints the demo password once

.\.venv\Scripts\python.exe manage.py runserver 127.0.0.1:8000   # terminal 1

# 5. Frontend (new terminal)
cd frontend
npm install
npm run dev                                                      # open http://localhost:5173
```
Demo users (after `seed_demo`): `admin@`, `security@`, `manager@`, `alice@`, `bob@` `demo.example`, all with the
printed password. Re-running `seed_demo` resets it; set `SECUREVAULT_DEMO_PASSWORD` to choose it yourself.

## Tests
```powershell
cd backend;  .\.venv\Scripts\python.exe -m pytest -q       # needs docker compose services up
cd frontend; npm test; npm run typecheck; npm run lint; npm run build
# real-browser smoke test against the running app: see docs/frontend.md
```

## Notes
- The browser only talks to `:5173`; Vite proxies `/api` and `/ws` to Django, so session and CSRF
  cookies are same-origin.
- A local PostgreSQL on port 5432 does not conflict: the Docker one is published on 5433.
- API docs: http://127.0.0.1:8000/api/docs/ (OpenAPI schema at `/api/schema/`) and [docs/api.md](docs/api.md).
- Production needs HTTPS, `config.settings.prod`, and a KMS/HSM for the key-encryption key (see docs/crypto.md).
