# FXI BotForge

FXI BotForge is a Persian-first community platform for discovering and sharing Telegram bot source projects.

## Implemented
- Persian RTL responsive landing page with live catalog search/category filters, sign-in and registration, personal dashboard, and administrator dashboard.
- Admin tools for reviewing submissions, suspending/reactivating users, archiving published sources, and inspecting audit history.
- Password hashing with PBKDF2, hashed opaque sessions, HttpOnly/Secure/SameSite cookies, and server-side role checks.
- D1 schema and first migration.
- Cloudflare KV-backed private ZIP submissions (5 MiB limit; KV is eventually consistent and intended for small/medium ZIP files), pending review, approve/reject workflow, published download endpoint, user notifications, and audit log.
- Owner bootstrap protected by deployment-only secrets.

## Stack
- Cloudflare Workers + Static Assets
- Cloudflare D1
- Cloudflare Workers KV (ZIP object storage)
- Vanilla HTML/CSS/JavaScript

## Local development
1. Install Node.js LTS and Wrangler: `npm install` is not required; run `npx wrangler dev`.
2. Create a D1 database and a Workers KV namespace in your Cloudflare account.
3. Update the D1 `database_id` and KV namespace `id` in `wrangler.toml`.
4. Apply the migration: `npx wrangler d1 migrations apply fxi-botforge-db --local`.
5. Create a local `.dev.vars` file (never commit it):
   ```
   BOOTSTRAP_OWNER_USERNAME=adminfxi
   BOOTSTRAP_OWNER_PASSWORD=your-owner-password
   ```
6. Start the app: `npx wrangler dev`.

## Cloudflare setup
1. Create a D1 database named `fxi-botforge-db` and a Workers KV namespace named `fxi-botforge-files`.
2. Confirm the D1 database ID and KV namespace ID in `wrangler.toml` match your Cloudflare account.
3. Run `npx wrangler d1 migrations apply fxi-botforge-db --remote`.
4. Add Worker secrets `BOOTSTRAP_OWNER_USERNAME` and `BOOTSTRAP_OWNER_PASSWORD` in Worker Settings → Variables and Secrets. Do not put secrets in GitHub.
5. Deploy the Worker with `npx wrangler deploy` (or connect the repository through Workers Builds).
6. Open `/setup-owner.html` once, create the owner account using the exact username/password configured as secrets, then sign in at `/login.html` using the generated 4-digit public user ID, username, and password. The bootstrap endpoint permanently closes after an owner/admin exists.
7. Check `/api/health`; it should report database connected and storage configured.

## Routes
- `/` public catalog
- `/login.html` sign in / register
- `/setup-owner.html` one-time owner bootstrap
- `/dashboard.html` upload submissions, review status, notifications
- `/admin.html` moderation queue, overview, user management, source management, audit log
- `GET /api/bots`, `GET /api/bots/:slug/download`
- `POST /api/submissions`, `GET /api/my/submissions`
- `GET /api/admin/overview`, `GET /api/admin/submissions`, `GET /api/admin/users`, `GET /api/admin/bots`
- `POST /api/admin/submissions/:id/approve|reject`
- `POST /api/admin/users/:id/suspend|activate`, `POST /api/admin/bots/:id/archive`

## Security notes
- Uploaded ZIP files stay in a private Workers KV namespace until approved. KV is eventually consistent; allow a short propagation delay after upload or approval.
- Current ZIP validation checks extension, size, and ZIP signature only. It is not malware scanning or a full archive integrity inspection. Review uploaded source code before approving it.
- No user-supplied file is executed by the platform.
- Use HTTPS in production. Keep the KV namespace and D1 binding server-side; do not expose storage credentials.
- Add rate limiting / Turnstile and automated dependency or secret scanning before opening the service to large-scale public use.

## Current limitations
- This initial version does not include password reset, email verification, public user profiles, advanced search/filtering, or automated malware scanning.
- Admin role assignment is intentionally not exposed to normal users; add admins through a controlled database operation.
