# E-Lection

E-Lection is a small end-to-end e-voting prototype built with a FastAPI backend and a static HTML/CSS frontend. It supports voter self-registration with email verification, Microsoft OAuth login, election and candidate management for admins, and live voting/results views for users.

## Features
- **User side:** register, verify via emailed code, Microsoft Sign-In, view active elections, cast votes, and see results/confirmation pages.
- **Admin side:** login, manage voters, candidates (with president/vice tickets), elections, and view dashboards with stats and recent activity.
- **Security:** email verification flow, admin auth, audit logging, and environment-driven configuration for secrets (Microsoft OAuth, SMTP, admin seed). Ballots use a hybrid scheme: a per-ballot AES-256-GCM session key encrypts voter_id + election_id + candidate_id + ticket_id + timestamp; that session key is encapsulated with ML-KEM-512 (via liboqs) and persisted in Redis. A separate `voter_election_status` table tracks whether a voter has cast a ballot for an election, keeping the primary `votes` table minimal.

## Tech Stack
- **Backend:** Python, FastAPI, SQLAlchemy
- **Frontend:** Static HTML + Tailwind/utility CSS (in `src/static/style.css`)
- **Database:** PostgreSQL
- **Auth:** Email verification + Microsoft OAuth (when configured)
- **Server:** Uvicorn (ASGI)

## Getting Started
1) **Prerequisites**
   - Python 3.11+
   - PostgreSQL running and reachable

2) **Install deps**
   ```bash
   pip install -r requirements.txt
   ```

3) **Environment**
   Set these as needed (examples):
   ```
   DATABASE_URL=postgresql+psycopg2://postgres:password@localhost:5432/demo
   MS_TENANT_ID=common
   MS_CLIENT_ID=your-microsoft-client-id
   MS_CLIENT_SECRET=your-microsoft-client-secret
   MS_REDIRECT_URI=http://127.0.0.1:8000/auth/microsoft/callback
   EMAIL_SENDER=election.noreply@gmail.com
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USERNAME=election.noreply@gmail.com
   SMTP_PASSWORD=your-app-password
   REDIS_URL=redis://localhost:6379/0
   SESSION_KEY_TTL_SECONDS=0  # optional; 0 keeps keys indefinitely
   ADMIN_EMAIL=felicia.kusuma294@gmail.com
   ADMIN_PASSWORD=Election.77
   ADMIN_FULL_NAME=Felicia Kusuma
   ```

4) **Run the app**
   ```bash
   uvicorn main:app --reload
   ```

5) **Useful URLs**
   - User login: `http://127.0.0.1:8000/login`
   - User dashboard: `http://127.0.0.1:8000/dashboard`
   - Admin login: `http://127.0.0.1:8000/admin`
   - Admin dashboard: `http://127.0.0.1:8000/admin-dashboard`

## Project Layout
- `main.py` – FastAPI entrypoint and middleware.
- `backend/routers` – API and page routes (auth, admins, candidates, elections, votes).
- `backend/services` – seeders, security, audit helpers.
- `backend/database.py` – DB engine and models.
- `src/` – HTML templates and static assets.
- `src/static/style.css` – global styling for user/admin pages.

## Notes
- Microsoft OAuth buttons appear only when `MS_CLIENT_ID`/`MS_CLIENT_SECRET` are set.
- Admin seeding depends on `ADMIN_EMAIL` and `ADMIN_PASSWORD`.
- Email verification requires working SMTP credentials.

## Railway Deploy Notes
- Link a PostgreSQL service and expose one of: `DATABASE_URL`, `DATABASE_PRIVATE_URL`, `DATABASE_PUBLIC_URL`, or `PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSWORD`.
- Set `SESSION_SECRET_KEY` to a strong random value in production.
- If you use vote decryption/counting features, link Redis and set `REDIS_URL`.
