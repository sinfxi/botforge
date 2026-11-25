# FXI BotForge

FXI BotForge is a Persian-first community platform for discovering and sharing Telegram bot source projects.

## Implemented
- Persian RTL responsive landing page with live catalog search/category filters, sign-in and registration, personal dashboard, and administrator dashboard.
- Admin tools for reviewing submissions, suspending/reactivating users, archiving published sources, and inspecting audit history.
- Password hashing with PBKDF2, hashed opaque sessions, HttpOnly/Secure/SameSite cookies, and server-side role checks.
- D1 schema and first migration.
- Cloudflare KV-backed private ZIP submissions (5 MiB limit; KV is eventually consistent and intended for small/medium ZIP files), pending review, approve/reject workflow, published download endpoint, user notifications, and audit log.
- One-time owner setup: the first visitor to submit a chosen 4-digit ID and password becomes the sole owner; the database enforces the single-owner rule.

- Custom F COIN services now fulfill immediately: each purchase is charged once, marked delivered, and receives a saved, account-specific starter document in purchase history. Service documents are generated from account/project metadata and clearly state when they are checklists or design briefs rather than source-code audits or finished graphic assets.
- Purchase history exposes the full delivered document, with an in-page copy action; the delivery record is stored separately in D1 and linked to the purchase.
- Daily F COIN check-ins with consecutive-day streaks, once-per-day atomic rewards, and a weekly 200-coin milestone.
- Cross-platform saved projects: bookmark published projects on the website or with `/save`, browse them from the member dashboard or `/favorites`, and remove them with `/unsave`.
- Project issue reporting from catalog cards or Telegram `/report <slug>`; reports are rate-limited, assigned tracking IDs, stored in D1, and notify the owner account.
- Expanded F COIN catalog with 34 active rewards, including instant profile/project perks and clearly marked manual services such as README polishing, performance review, security hardening plans, and launch kits.
- Owner and manager audit controls now enforce the dedicated announcements permission, including announcement APIs.

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
5. Open `/setup-owner.html` before anyone else. Enter a 4-digit ID, a username (3–24 letters/numbers/underscores), and a password (10–200 characters). The first successful submission becomes the sole owner; later setup attempts are rejected and the setup form closes.
6. Sign in at `/login.html` using only the chosen 4-digit ID and password. The login form also accepts Persian or Arabic numerals.
7. Check `/api/health`; it should report database connected and storage configured.

## Routes
- `/` public catalog
- `/login.html` sign in / register
- `/setup-owner.html` one-time owner bootstrap
- `/dashboard.html` upload submissions, review status, notifications
- `/admin.html` moderation queue, overview, user management, source management, audit log
- `GET /api/bots`, `GET /api/bots/:slug/download`, `POST /api/community/checkin`
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
- View account details, public creator profiles, published projects, submission history, wallet balance, purchase history, active perks, and recent N Coin transactions.
- Browse and search the public project catalog, then download published project files directly in Telegram.
- Submit a project ZIP from Telegram through a guided flow: title, description, category, rights confirmation, and ZIP document upload (5 MiB maximum).
- Claim eligible one-time lucky-ID rewards, browse and purchase N Coin rewards with a confirmation step, and redeem gift codes.
- Track submission decisions with `/track`, view report status with `/myreports` and `/trackreport`, read notifications and announcements, message support, and unlink the Telegram account.
- The permission-checked manager menu is available only to linked, active manager accounts. Its Telegram reply-keyboard shortcuts support:
- Reviewing pending submissions with one-tap `/approve` and `/reject` buttons; the same permission checks, publication flow, user notification, audit record, and 50 N Coin approval reward are applied.
- Searching for a user by 4-digit public ID, viewing account status, published project count and N Coin balance, and activating/suspending eligible user accounts after a second confirmation.
- Browsing published projects and archiving one from its Telegram button; archived files are removed from KV and the action is audited.
- Viewing open project reports and resolving them with user notification.
- Viewing open N Coin orders and approving, delivering, or rejecting them only after a second confirmation. Order actions are restricted to the primary account; rejection refunds the wallet atomically.
- Opening the private support inbox, reading recent conversations, and replying to users from Telegram. Replies are saved to the same `owner_messages` table used by the website and are sent to the user's linked Telegram chat when available.
- Viewing permission-scoped platform statistics and opening the web admin panel.

Sensitive account and purchase actions use a confirmation step; pending confirmations and chat replies expire with the existing 30-minute Telegram state timeout. The bot uses the same D1 records, KV file storage, reward catalog, entitlement rules, saved-project list, and audit log as the website. It does not create a second wallet or account database.

User commands: `/menu`, `/account`, `/catalog`, `/search`, `/download`, `/find`, `/favorites`, `/save`, `/unsave`, `/report`, `/myreports`, `/trackreport`, `/track`, `/history`, `/projects`, `/submit`, `/wallet`, `/rewards`, `/gift`, `/notifications`, `/support`, `/help`. Manager accounts can also use `/admin`.

After deploying an updated bot, an owner should open the BotForge admin panel and run **ثبت وب‌هوک در تلگرام** once to refresh Telegram's command list.


## Latest Telegram and community improvements
- Persistent Telegram chat keyboard now includes daily reward check-in and an account status summary.
- `/checkin` safely claims the same daily N Coin streak reward as the website, with a database-level duplicate guard shared across both channels.
- `/status` summarizes published projects, submission queue, wallet, active benefits, unread notifications and current check-in streak.
- Community page now visualizes the last seven days of check-in progress with responsive streak tiles.
