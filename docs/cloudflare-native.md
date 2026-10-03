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

## Multiple Passkeys

After signing in, open **Passkeys** on the homepage or **我的 Passkeys** in Management, then choose **添加 Passkey**. The same compact dialog lists the account's existing credentials. **保存到 → 安全密钥（USB / NFC）** explicitly requests a cross-platform authenticator; automatic selection retains the configured browser behavior. Both choices retain server-side verified-user acceptance, allowed algorithms and discoverable-credential policy. A platform-only administrator policy still prevents external-key enrollment. An explicit attachment improves browser routing but cannot guarantee hardware-specific Safari behavior.

Both choices and reauthentication request `userVerification: "required"`. The server uses `verifyRegistrationResponse({requireUserVerification: true})` and separately requires `registrationInfo.userVerified`; a response without signed UV is rejected without creating a credential. Both registration paths send the account username as `user.displayName` as well as `user.name`, while `user.id` remains the stable identity handle. Existing-credential exclusion remains intact, including disabled keys; no authenticator is allowed to bypass duplicate checks as a compatibility workaround.

Enrollment preserves the identity, permissions and existing credentials; it also works while public registration is closed. A verified login older than five minutes triggers an inline Passkey reauthentication before enrollment, without leaving the page. Cancelling creates no credential. A synced Passkey is already usable on devices sharing its credential provider; enrollment excludes existing credentials, including disabled ones, to avoid registering the same credential again.

Administrators manage each credential under **用户 → 管理**, not the global Passkey-settings page. Each row has its own enable/disable and delete actions. Changing a credential's status or deleting it revokes that user's existing sessions and OAuth access tokens; restoring a key does not restore old sessions. An administrator cannot disable or delete their own final active Passkey, including during concurrent requests. Deleting a credential from the service does not delete it from the user's device or password manager.

Migration `0002_credential_status.sql` adds nullable `disabled_at` and a user/status index. Existing identities and credentials remain intact and enabled. Apply all numbered migrations with Wrangler before deploying this version; the test harness likewise applies the entire migration sequence.

The new same-origin browser endpoints are `GET /api/account/passkeys`, `POST /api/account/passkeys/options` and `POST /api/account/passkeys/verify`. The GET response includes `ok`, `username`, `csrfToken`, and `passkeys` with `id`, timestamps, device/backup state and `disabledAt`; it excludes credential material. POST bodies require `csrfToken`; verification also requires the WebAuthn `credential`. Options optionally accepts `authenticator: "security-key"` (omit for automatic selection; other values return 400), returning `{ok, publicKey}`; verification returns `{ok}`. Both POSTs require a valid session and recent user verification (`403` with `reauthRequired: true` otherwise). They use a separate, expiring session-bound ceremony and an atomic D1 guard for one-time consumption. Existing external OAuth contracts are unchanged.

The existing administrator credential path `/api/management/users/:userId/credentials/:credentialId` accepts `DELETE` and now `PATCH` with `{disabled: boolean}`. Both retain the signed Management channel, CSRF, fresh verification, rotating operation token and audit requirements. Ownership and credential status are checked again in the same D1 transaction as the mutation.

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

Native channel responses advertise `nonce_mode: "ack"`. The server rotates its nonce atomically after a successful signed ACK, while SSE only reports current state and rechecks authorization. The browser serializes ACKs and Management writes, waits for channel initialization, and ignores late SSE nonce snapshots in this mode. This prevents network latency from invalidating an in-flight proof; replay and stale-counter rejection remain enforced by D1. The browser retains the legacy SSE nonce mode for the historical local Python UI.

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
| Multiple Passkeys, credential enable/disable/removal, user permissions and revocation | `auth.ts` and `management.ts`; self-service enrollment, user-specific credential controls, last-key/last-admin protection, real D1 guard/rollback and browser tests |
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
