# SecureVault

Zero-trust enterprise credential & access management platform (educational MVP).

> **Crypto model:** server-side envelope encryption (AES-256-GCM, per-record data keys wrapped by a
> key-encryption key, separate HMAC blind-index key). SecureVault is **not** a zero-knowledge system:
> the server can decrypt when policy allows. See the Phase 1 architecture decision.

## Layout

```
backend/    Django 5.2 + DRF + Channels (config/ = settings & ASGI, apps/ = domain apps)
frontend/   React 19 + TypeScript + Vite + Tailwind 4 (Vitest for tests)
docker-compose.yml   PostgreSQL 16 (host port 5433) + Redis 7 (host port 6379), loopback only
.env.example         placeholders only; copy to .env
```

## First-time setup (Windows PowerShell)

```powershell
# 1. Secrets/config
Copy-Item .env.example .env
# edit .env: set DJANGO_SECRET_KEY and POSTGRES_PASSWORD (see the generator command in the file)

# 2. Services (Docker Desktop must be running)
docker compose up -d
docker compose ps            # both should be "healthy"

# 3. Backend
python -m venv backend\.venv
backend\.venv\Scripts\python.exe -m pip install -r backend\requirements-dev.txt
cd backend
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py runserver 127.0.0.1:8000   # terminal 1

# 4. Frontend (new terminal)
cd frontend
npm install
npm run dev                                                     # http://localhost:5173
```

## Tests

```powershell
cd backend;  .\.venv\Scripts\python.exe -m pytest -v     # needs docker compose services up
cd frontend; npm test; npm run typecheck; npm run lint
```

## Notes

- The browser only talks to `:5173`; Vite proxies `/api` and `/ws` to Django, so session and CSRF
  cookies are same-origin.
- A local PostgreSQL on port 5432 does not conflict: the Docker one is published on 5433.
- API docs: http://127.0.0.1:8000/api/docs/ (OpenAPI schema at `/api/schema/`).
- `/ws/ping/` is a foundation smoke test only; the authenticated event channel arrives with lockdown.
