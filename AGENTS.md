# AGENTS.md

This repository welcomes agentic coding work. Optimize for small, correct, well-tested changes that preserve the passkey-first user experience.

## Start Here

Read the project Wiki before broad changes:

- Project overview: https://github.com/jasonhejiahuan/Passkey-Auth/wiki
- Agent guide: https://github.com/jasonhejiahuan/Passkey-Auth/wiki/Development
- Authentication flows: https://github.com/jasonhejiahuan/Passkey-Auth/wiki/Authentication-Flows
- Security model: https://github.com/jasonhejiahuan/Passkey-Auth/wiki/Security

## Project Map

- `worker/src/index.ts`: native Worker routing, request context, security headers and scheduled cleanup.
- `worker/src/auth.ts`: registration, passkeys, login and trusted-operator recovery.
- `worker/src/oauth.ts`: OAuth/PKCE, link challenges, server verification and demos.
- `worker/src/store.ts`, `worker/migrations/`: authoritative D1 state, guarded transactions and versioned schema.
- `worker/src/management.ts`: Management permissions, signed channels, rotating operation tokens, exports and settings.
- `worker/src/telemetry.ts`: optional collection, privacy policy, built-in/Jason/custom delivery and reporting.
- `worker/src/pages.ts`, `worker/scripts/build-assets.mjs`: precompiled original templates and static assets.
- `worker/test/`: native workerd/D1 security tests and local/public browser acceptance.
- `jstu_passkey/static/`, `jstu_passkey/templates/`: shared original UI source.
- `jstu_passkey/*.py`, `tests/`, `integrations/`: legacy desktop/reference implementation, not a cloud backend.
- `docs/cloudflare-native.md`, `docs/cloudflare-validation.md`: current operations and measured verification.

## Safety Invariants

Keep these true:

- WebAuthn challenges are generated server-side and verified server-side.
- OAuth `state` is required and must be checked before token exchange.
- Authorization codes are single-use and bound to `client_id` plus `redirect_uri`.
- Link challenges are single-use; `status=success` is display-only, never auth proof.
- `client_secret`, server API tokens, session cookies, access tokens, and raw credentials must not be exposed in browser UI or committed.
- Registration stays disabled by default.
- The native database is intentionally fresh-start only. Apply numbered D1 migrations; never edit an applied migration or add a legacy data-import path.
- Management writes require admin session, CSRF, recent Passkey authentication,
  and the current rotating action token.
- Recovery tokens are operator-created, one-use, hash-only, time-limited, session-bound during registration and consumed atomically.
- `PASSKEY_ORIGIN` must match the browser origin used for WebAuthn.
- Telemetry collection tokens are short-lived, policy-bound, one-use, and never
  identity or authorization proof.
- The telemetry master switch must stay a true hot-path short circuit: when off,
  do not query telemetry event tables, rewrite HTML, load telemetry JS, or create
  browser network work. Explicit administrator requests may inspect stored history while collection is off.
- External telemetry API keys and private headers stay server-side. Direct browser
  delivery may use only a short-lived external target or explicitly public headers.
- Unselected telemetry backends must not create external requests or initialize active delivery state.

## Development Loop

The supported server is the native Cloudflare Worker in `worker/`. For current changes run `cd worker && npm run typecheck && npm test && npm run build`. Browser regressions run `node test/browser/run.mjs`. Original templates/static remain the UI source. Python tests below only validate the archived local/desktop implementation.

Legacy tests:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

For legacy desktop browser testing only:

```bash
PORT=5003 PASSKEY_ORIGIN=http://localhost:5003 .venv/bin/python -m jstu_passkey.app
```

If you touch UI, check desktop and mobile layouts. If you touch auth, OAuth, storage, or config, add or update tests.

The management UI extends the existing black/white design language with a responsive
sidebar, dense desktop rows, mobile cards, light/dark mode, and explicit confirmation
for destructive actions.

## Change Style

- Prefer focused patches over broad rewrites.
- Follow native Workers TypeScript, D1 transaction semantics, and the existing plain JavaScript UI. Do not add a VPS/Python runtime dependency.
- Keep the UI quiet, modern, and user-first.
- Keep documentation in sync with behavior.
- Do not commit `.env`, SQLite databases, `.venv`, `.DS_Store`, generated caches, or real secrets.
