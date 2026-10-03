# Native Cloudflare service

The supported server is `worker/`: TypeScript Workers, D1, Web Crypto, and SimpleWebAuthn. There is no request path to a Python server, VPS, Linux service, or third-party identity provider. Original templates, styles, icons and browser scripts remain the UI source. A build step precompiles the templates; the Worker has no template compiler/eval or filesystem dependency.

## Local initialization

Use Node 22 or newer. From `worker/`:

```sh
npm ci
npm run db:local
npm run operator -- demo-client --origin http://localhost:8787
npm run operator -- recovery --origin http://localhost:8787
npm run dev
```

The recovery command stores the one-use URL in `worker/.local/`, with file mode 0600; open that file locally, visit its URL within 15 minutes, choose a username and create a Passkey. This identity has all Management permissions. No first-visitor rule exists. Recovery registration requires authenticator user verification. Later operator recovery creates an additional administrator, without converting a random public registration into an administrator.

Public registration remains closed until changed in Management or with `npm run operator -- registration open`. General login may use a username or a discoverable Passkey. Management writes always need recent verified authentication even when general login permits presence-only credentials.

## Cloud initialization

Prefer the connected Cloudflare MCP for account/resource discovery and scoped deployment. Wrangler remains the reproducible local build/migration tool and an authenticated deployment fallback. Only create/select this project's database; never delete or rebuild an account-wide resource.

1. Create the project D1 database and put its ID in `worker/wrangler.jsonc`. Apply `worker/migrations/` in numeric order. Wrangler records each applied migration in `d1_migrations`; future migrations append files, never edit an applied migration.
2. Set `PASSKEY_RP_ID` to the final hostname and `PASSKEY_ORIGIN` to its exact HTTPS origin. Set the optional name. Configure the Worker custom domain. WebAuthn credentials are RP-bound: changing the RP hostname later requires new credentials.
3. If server session verification is needed, install a random 32-byte `PASSKEY_SERVER_API_TOKEN` as a Worker secret. There are no password credentials. New OAuth client secrets and all internal tokens are cryptographically random 256-bit values; the database stores SHA-256 hashes, never their plaintext. Do not import weak manually chosen secrets into this schema.
4. Build/deploy, initialize the demo client with the final origin, then issue an operator recovery grant using the remote database. `npm run operator -- recovery --origin https://auth.example.com --remote` writes the private bootstrap file without printing the URL into logs.
5. Register the administrator, review settings and create clients in Management. A client secret is shown once at creation/rotation. Keep it in the consuming application's server secret store.

The HTTP hostname must match `PASSKEY_ORIGIN`; a workers.dev alias is deliberately unavailable when the final custom domain is configured. Do not create a second RP accidentally during tests.

## Distributed security

D1 is authoritative for sessions, challenges, reservations, OAuth requests/codes/access tokens, recovery grants, management channel counters/nonces and action tokens. No process memory or eventually consistent cache decides authorization. An opaque HttpOnly/SameSite=Lax browser cookie selects a server session. Login rotates the session; reauthentication preserves the signed Management channel binding. All identity tokens refer to a stable random `user_handle`, independent of username.

`Store.guardBatch` checks authorization inside the transaction, using a CHECK constraint to abort the entire batch on stale authorization. Challenge/code consumption, credential counters, token rotation, business writes and audit records commit together. Duplicate requests cannot both win, and failed writes leave the previous action token usable. User disablement, session-version changes, client disablement and platform-policy changes are checked at the relevant operation; access tokens do not carry a stale permission snapshot.

Management retains CSRF, a five-minute verified reauthentication window, rotating operation tokens, P-256 signed proofs, monotonic counters and server nonces. SSE responses are short; EventSource reconnects at the server-provided retry interval, and every request rechecks authorization. There is no long-lived in-memory channel authority.

Registration is closed by default. Only a trusted Cloudflare operator can create recovery grants. The original full provider permissions (admin/login/demo plus per-client policy) remain; business/Team permissions belong to the consuming application, not this identity provider.

## UI and compatibility

Routes and response shapes remain compatible with the existing OAuth, passkey, management and demo flows. PKCE S256, `screen_hint=signup`, `login_hint`, fresh authentication when reusing an existing username, and the legacy Hyping error redirect are retained. This is OAuth, not OIDC. There are no ID tokens or invented JWKS endpoints.

The existing plain HTML/CSS/JavaScript UI is reused. The implementation changes do not add architecture copy, helper paragraphs or a new component framework. Demo result details redact credentials rather than echoing live codes/access tokens into HTML. Necessary errors remain visible. Username uniqueness uses NFKC normalization plus Unicode lowercase for newly created identities; this is a deliberate fresh-schema rule, not a legacy casefold migration.

The cookie and internal token encodings have changed. Test accounts, clients and credentials must be recreated; there is no import or dual-write path. Server verification callers continue supplying the opaque `sessionCookie` value, rather than attempting to decode it themselves.

## Capability inventory

| Existing capability | Native implementation and verification |
| --- | --- |
| Registration gate, lazy registration module, custom username | `auth.ts`; original `/api/ui/intent`, `/api/ui/register-client.js`, `/api/register/options` and `/verify`; real signed registration and browser tests |
| Named/discoverable login, in-place homepage, reauthentication | `auth.ts`; original `/auth/passkey`, `/flow`, `/options`, `/verify`, `/api/me`, `/api/logout`; UV and session-rotation regressions |
| Passkey inventory/removal, user permissions and revocation | `management.ts`; original Management APIs, last-admin protection, real D1 guard/rollback tests |
| OAuth, PKCE, signup and existing identity reuse | `oauth.ts`; original authorize/complete/token/userinfo/discovery contract; concurrent code consumption and public HTTPS browser test |
| Link challenge and server verification | `oauth.ts`; existing browser routes and `/api/server/session/verify`; new client-authenticated challenge create/consume HTTP APIs replace Python imports |
| Trusted administrator initialization/recovery | Private operator-created D1 grant; original token-path UI/options/verify, strong UV, single-use transactional consumption |
| Signed Management channel and rotating write tokens | D1 sessions/channel counters/nonces, Web Crypto signatures, recent UV, CSRF, bounded SSE; replay/revocation/concurrency tests |
| Audit, login history, exports, settings and cleanup | Original Management views and routes; indexed D1 records, CSV/formula protection, scheduled expiry and telemetry retention tests |
| Optional telemetry and integrations | `telemetry.ts`; original browser-token/collect/direct-target and Management APIs; policy, backend, relay/direct, pairing and cleanup tests |
| Original example applications | `/demo/oauth`, `/demo/third-party`, `/demo/link-login` and callbacks; all three local browser flows, with secret redaction |

The complete cloud acceptance uses virtual CTAP2 credentials. Hardware-specific Safari/iCloud/Android behavior and an operator's real external telemetry endpoint remain separate acceptance checks.

## Telemetry and limits

Telemetry is off by default. The authoritative master setting is checked before telemetry-table access, HTML injection, collector loading or external requests. An always-current D1 setting read replaces the old process-local boolean: it costs a query but allows another Worker instance to stop collection immediately. Enabled telemetry preserves per-user policy, built-in/Jason/custom backends, relay/direct delivery, statistics, export and cleanup. Secrets remain server-side; direct custom delivery cannot expose private headers. Remote endpoints must be HTTPS and publicly reachable; private localhost/LAN collectors are not reachable from Cloudflare.

Static assets use Workers Assets. Scheduled cleanup removes expired ephemeral authentication state and applies telemetry retention. Storage/CPU/network costs depend on actual use, especially an open Management tab or enabled external telemetry. No product or security capability is silently disabled to fit a free-tier estimate.

Cloudflare's current documented Free limits include 100,000 Worker requests/day, 10 ms CPU/request, and D1 5 million rows read/day, 100,000 rows written/day, 5 GB total storage. These are account-level constraints, not a guarantee of free operation. Production validation must include Worker CPU measurements, D1 query metrics and realistic browser flows. A local workerd pass is not a paid/free classification, and wall-clock HTTP latency is not CPU time. See the delivery report for measured results and any remaining limits.

Sources: [Workers limits](https://developers.cloudflare.com/workers/platform/limits/), [D1 pricing](https://developers.cloudflare.com/d1/platform/pricing/), [D1 batch semantics](https://developers.cloudflare.com/d1/worker-api/d1-database/#batch).

## Legacy Python and desktop workflows

The Python modules and tests remain as a reference for the original UI and business semantics. They are not a production backend or a fallback for the Worker. The old Linux provision/backup path is retired; never launch it as part of Cloudflare setup. Previously published standalone desktop apps keep their own local database and do not share Cloudflare identity state. The desktop build workflow is retained only as a manually invoked legacy build; a new cloud release does not automatically build or publish a second local authentication server.

The retained Python dependencies require cryptography 49 to fix [CVE-2026-69249](https://github.com/pyca/cryptography/security/advisories/GHSA-jwv3-5hgf-82ww). [Version 49 removed macOS Intel support](https://cryptography.io/en/49.0.0/changelog/#v49-0-0), so that desktop build target has been removed. Intel Mac users can use the Cloudflare service in a browser. Manual builds remain available for macOS ARM64, Windows x64, and Linux x64.

Use `npm run dev` for current local development. No old SQLite database, session, authorization code or passkey migration is provided because this deployment starts with disposable test identities.
