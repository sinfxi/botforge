# FXI BotForge

A Persian-first platform for discovering, submitting, reviewing, and publishing Telegram bot source code.

## Project workflow

- Browse published Telegram bot projects and download approved source archives.
- Submit a source archive with a title, description, category, and publication-rights confirmation.
- Keep every new submission private while it awaits administrator review.
- Let administrators approve or reject submissions.
- Publish approved projects and notify their submitters in the application.

## Planned technology

- Cloudflare Workers and Static Assets
- Cloudflare D1 for application data
- Cloudflare R2 for private source archives
- Responsive HTML, CSS, and JavaScript interface

## Security requirements

- Enforce authentication and authorization on the server.
- Store uploaded archives privately until approval.
- Validate archive type and size; never trust client-provided filenames or MIME types.
- Keep secrets in deployment environment variables, never in source control.
- Record sensitive administrative actions in an audit log.
- Require submitters to confirm they have the rights needed to share their source.

## Project status

Initial project documentation. Application implementation, database migrations, tests, and Cloudflare deployment configuration are being added incrementally.

## Development

Local setup and deployment instructions will be documented as the application is implemented.
