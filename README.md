# VMAXweb — Web & API Security Engine

VMAXweb is a full-stack security audit tool: FastAPI engine (6 scanners + scoring + SSRF safety), Next.js UI, Supabase persistence + auth, and branded PDF reports.

## Quick Start

### Backend
```bash
cd backend
PYTHONPATH=/home/heisenberg/VMAXweb/backend python3 -m uvicorn app.main:app --reload
```

### Frontend
```bash
cd frontend
npm run dev
```

Default: API at http://localhost:8000, UI at http://localhost:3000.

## Environment

### Backend
Copy `.env.example` or set:
- `VMAX_CORS_ORIGINS` (e.g. `["http://localhost:3000"]`)
- `VMAX_SUPABASE_URL`, `VMAX_SUPABASE_SERVICE_KEY` (optional; enables persistence)
- `VMAX_SUPABASE_JWT_SECRET`, `VMAX_AUTH_REQUIRED` (optional)
- `VMAX_FREE_MONTHLY_SCAN_LIMIT` (default 5)

### Frontend
Copy `.env.local.example`:
- `NEXT_PUBLIC_API_URL`
- `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`
- `NEXT_PUBLIC_SITE_URL`

## Features
- 6 scanners: Headers, TLS, API/CORS, Sensitive files, Ports (verified-only), Subdomains (verified-only)
- SSRF protection + DNS TXT verification gating
- In-memory or Supabase-backed storage + JWT auth
- Free plan limit (5/month), Pro bypass
- Branded PDF reports (fpdf2)
- History UI + magic link auth

## Endpoints
- `POST /api/v1/scan`, `GET /api/v1/scans`, `GET /api/v1/scans/{id}`, `GET /api/v1/scans/{id}/report`
- `GET /api/v1/me`, `GET /api/v1/modules`, `GET /healthz`

## Supabase
Apply `supabase/migrations/0001_init.sql` in your project.
