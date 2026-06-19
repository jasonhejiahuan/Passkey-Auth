# AGENTS.md

This repository welcomes agentic coding work. Optimize for small, correct, well-tested changes that preserve the passkey-first user experience.

## Start Here

Read the project Wiki before broad changes:

- Project overview: https://github.com/jasonhejiahuan/Passkey-Auth/wiki
- Agent guide: https://github.com/jasonhejiahuan/Passkey-Auth/wiki/Agents-Vibe-Coding-Guide
- OAuth integration: https://github.com/jasonhejiahuan/Passkey-Auth/wiki/OAuth-and-SSO-Integration
- Security model: https://github.com/jasonhejiahuan/Passkey-Auth/wiki/Security-Model

## Project Map

- `passkey_demo/app.py`: Flask routes, OAuth flow, link challenge flow, session verify API.
- `passkey_demo/config.py`: default config values and environment overrides.
- `passkey_demo/storage.py`: SQLite users, credentials, OAuth codes, challenge requests.
- `passkey_demo/management.py`: `/management` UI APIs, permissions, CSV export, and log cleanup.
- `passkey_demo/webauthn_service.py`: WebAuthn option generation and verification.
- `passkey_demo/static/`: browser passkey flows and UI behavior.
- `passkey_demo/templates/`: minimal Auth WebUI and demo pages.
- `tests/`: config, registration gate, OAuth, and challenge flow tests.

## Safety Invariants

Keep these true:

- WebAuthn challenges are generated server-side and verified server-side.
- OAuth `state` is required and must be checked before token exchange.
- Authorization codes are single-use and bound to `client_id` plus `redirect_uri`.
- Link challenges are single-use; `status=success` is display-only, never auth proof.
- `client_secret`, server API tokens, session cookies, access tokens, and raw credentials must not be exposed in browser UI or committed.
- Registration stays disabled by default.
- The v2 database is intentionally fresh-start only; do not add legacy schema migrations or old `PASSKEY_OAUTH_DEMO_*` aliases.
- Management writes require admin session, CSRF, and recent Passkey authentication.
- Recovery tokens are one-use, hash-only, and must be validated before the server starts.
- `PASSKEY_ORIGIN` must match the browser origin used for WebAuthn.

## Development Loop

Run tests with the local virtualenv:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

For local browser testing:

```bash
PORT=5003 PASSKEY_ORIGIN=http://localhost:5003 .venv/bin/python -m passkey_demo.app
```

If you touch UI, check desktop and mobile layouts. If you touch auth, OAuth, storage, or config, add or update tests.

The management UI extends the existing black/white design language with a responsive
sidebar, dense desktop rows, mobile cards, light/dark mode, and explicit confirmation
for destructive actions.

## Change Style

- Prefer focused patches over broad rewrites.
- Follow existing Flask, SQLite, and plain JavaScript patterns.
- Keep the UI quiet, modern, and user-first.
- Keep documentation in sync with behavior.
- Do not commit `.env`, SQLite databases, `.venv`, `.DS_Store`, generated caches, or real secrets.
