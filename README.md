# FXI BotForge

FXI BotForge is a Persian-first community platform for discovering and sharing Telegram bot source projects.

## Implemented
- Persian RTL responsive landing page with live catalog search/category filters, sign-in and registration, personal dashboard, and administrator dashboard.
- Admin tools for reviewing submissions, suspending/reactivating users, archiving published sources, and inspecting audit history.
- Password hashing with PBKDF2, hashed opaque sessions, HttpOnly/Secure/SameSite cookies, and server-side role checks.
- D1 schema and first migration.
- Cloudflare KV-backed private ZIP submissions (5 MiB limit; KV is eventually consistent and intended for small/medium ZIP files), pending review, approve/reject workflow, published download endpoint, user notifications, and audit log.
- One-time owner setup: the first visitor to submit a chosen 4-digit ID and password becomes the sole owner; the database enforces the single-owner rule.

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
5. Start the app: `npx wrangler dev`. The first person to submit the owner setup form chooses the 4-digit ID and password.

## Cloudflare setup
1. Create a D1 database named `fxi-botforge-db` and a Workers KV namespace named `fxi-botforge-files`.
2. Confirm the D1 database ID and KV namespace ID in `wrangler.toml` match your Cloudflare account.
3. Run `npx wrangler d1 migrations apply fxi-botforge-db --remote`.
4. Deploy the Worker with `npx wrangler deploy` (or connect the repository through Workers Builds).
5. Open `/setup-owner.html` before anyone else. Enter a 4-digit ID of your choice and any password (1–200 characters). The first successful submission becomes the sole owner; later setup attempts are rejected and the setup form closes.
6. Sign in at `/login.html` using only the chosen 4-digit ID and password. The login form also accepts Persian or Arabic numerals.
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

## Telegram account workspace

The connected `@FxiCode_bot` account can manage the core user workspace without opening the website:
- Link through the website's one-time code or request a link with `/connect 1234` and confirm it while signed in on the website.
- View account details, published projects, submission history, wallet balance, and recent N Coin transactions.
- Submit a project ZIP from Telegram through a guided flow: title, description, category, rights confirmation, and ZIP document upload (5 MiB maximum).
- Claim eligible one-time lucky-ID rewards, browse and purchase N Coin rewards with a confirmation step, and redeem gift codes.
- Read notifications and announcements, message support, and unlink the Telegram account.
- The existing permission-checked manager menu remains separate and is shown only to linked active manager accounts.

The bot uses the same D1 records, KV file storage, reward catalog, entitlement rules, and audit log as the website. Telegram user state is stored in D1 and expires after 30 minutes of inactivity. It does not create a second wallet or account database.

User commands: `/menu`, `/account`, `/projects`, `/submit`, `/wallet`, `/rewards`, `/gift`, `/notifications`, `/support`, `/help`. Manager accounts can also use `/admin`.

After deploying an updated bot, an owner should open the BotForge admin panel and run **ثبت وب‌هوک در تلگرام** once to refresh Telegram's command list.
