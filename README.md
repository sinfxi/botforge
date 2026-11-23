# FXI BotForge

FXI BotForge is a Persian-first community platform for discovering and sharing Telegram bot source projects.

## Implemented
- Persian RTL responsive landing page, sign-in and registration, personal dashboard, and administrator review dashboard.
- Password hashing with PBKDF2, hashed opaque sessions, HttpOnly/Secure/SameSite cookies, and server-side role checks.
- D1 schema and first migration.
- R2-backed private ZIP submissions (5 MiB limit), pending review, approve/reject workflow, published download endpoint, user notifications, and audit log.
- Owner bootstrap protected by deployment-only secrets.

## Stack
- Cloudflare Workers + Static Assets
- Cloudflare D1
- Cloudflare R2
- Vanilla HTML/CSS/JavaScript

## Local development
1. Install Node.js LTS and Wrangler: `npm install` is not required; run `npx wrangler dev`.
2. Create a D1 database and an R2 bucket in your Cloudflare account.
3. Update the D1 `database_id` in `wrangler.toml` and ensure the bucket name matches.
4. Apply the migration: `npx wrangler d1 migrations apply fxi-botforge-db --local`.
5. Create a local `.dev.vars` file (never commit it):
   ```
   BOOTSTRAP_OWNER_EMAIL=you@example.com
   BOOTSTRAP_OWNER_PASSWORD=use-a-long-unique-password
   ```
6. Start the app: `npx wrangler dev`.

## Cloudflare setup
1. Create a D1 database named `fxi-botforge-db` and an R2 bucket named `fxi-botforge-files`.
2. Copy the D1 database ID into `wrangler.toml` in place of `REPLACE_WITH_D1_DATABASE_ID`.
3. Run `npx wrangler d1 migrations apply fxi-botforge-db --remote`.
4. Add Worker secrets `BOOTSTRAP_OWNER_EMAIL` and `BOOTSTRAP_OWNER_PASSWORD` in Worker Settings → Variables and Secrets. Use a unique password; do not put secrets in GitHub.
5. Deploy the Worker with `npx wrangler deploy` (or connect the repository through Workers Builds).
6. Open `/setup-owner.html` once, create the owner account using the exact email/password configured as secrets, then sign in at `/login.html`. The bootstrap endpoint permanently closes after an owner/admin exists.
7. Check `/api/health`; it should report database connected and storage configured.

## Routes
- `/` public catalog
- `/login.html` sign in / register
- `/setup-owner.html` one-time owner bootstrap
- `/dashboard.html` upload submissions, review status, notifications
- `/admin.html` moderation queue, overview, audit log
- `GET /api/bots`, `GET /api/bots/:slug/download`
- `POST /api/submissions`, `GET /api/my/submissions`
- `GET /api/admin/overview`, `GET /api/admin/submissions`
- `POST /api/admin/submissions/:id/approve|reject`

## Security notes
- Uploaded ZIP files stay in a private R2 bucket until approved.
- Current ZIP validation checks extension, size, and ZIP signature only. It is not malware scanning or a full archive integrity inspection. Review uploaded source code before approving it.
- No user-supplied file is executed by the platform.
- Use HTTPS in production. Keep D1 and R2 private; do not expose bucket credentials.
- Add rate limiting / Turnstile and automated dependency or secret scanning before opening the service to large-scale public use.

## Current limitations
- This initial version does not include password reset, email verification, public user profiles, advanced search/filtering, or automated malware scanning.
- Admin role assignment is intentionally not exposed to normal users; add admins through a controlled database operation.
