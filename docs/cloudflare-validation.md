# Cloudflare migration validation

Implementation and validation completed on 2026-10-03 in the existing Passkey-Auth repository, branch `codex/cloudflare-native`. This record separates local proof, deployed behavior and the remaining Free-tier uncertainty.

## Initial migration baseline and local evidence

- Includes the effective PR #11 OAuth/PKCE/signup changes and the original checkout's uncommitted in-place homepage login change. No automatic PR merge occurred. The original dirty checkout and PPQ were not modified.
- 34 Python baseline screenshots and 29 native screenshots: desktop 1280×900, mobile 390×844, dark appearance, registration, recovery, demos and all eight Management views. Local artifacts are retained under ignored `.cache/validation/python-baseline/` and `.cache/validation/native/`.
- 21 original HTML fixtures, escaping/redaction tests and byte comparisons preserve the original static CSS, browser JavaScript and Logo. Settled homepage and registration screenshots match pixel-for-pixel. The link-demo form gains only an invisible CSRF field.
- `npm run typecheck`, `npm test` and `npm run build` passed on the final source. **85 tests across 6 files** exercise actual workerd/D1, not Python or a mock database.
- Coverage includes atomic single-use operations, guarded rollback, concurrent authorization/code consumption, real P-256 WebAuthn registration/assertion verification, user/session/client revocation, server session verification, signed Management requests, rotating tokens, telemetry policy/delivery, and scheduled expiry/retention with valid-record preservation.
- `node test/browser/run.mjs` passed: recovery with UV, named/discoverable and in-place homepage login, signup, PKCE/userinfo, stable existing identity reuse, Management autosave/CSV and all three demos. No JavaScript errors. Local databases and virtual authenticators are destroyed after the run.
- Production npm dependency audit reports zero known vulnerabilities (`npm audit --omit=dev`). The retained desktop dependency was updated to cryptography 49.0.0 for [CVE-2026-69249](https://github.com/pyca/cryptography/security/advisories/GHSA-jwv3-5hgf-82ww); `pip check` and **129 legacy Python tests** pass in an isolated environment. Those tests establish legacy compatibility only, not Worker correctness. Upstream removed macOS Intel support, so that manual packaging target is explicitly retired; macOS ARM64, Windows and Linux targets remain.
- GitHub Native Worker verification and CodeQL/AI checks passed for the native implementation commit; no code-scanning findings were reported on this branch.
- Bundle: 1,032.73 KiB uncompressed / 190.78 KiB gzip; observed final deployment startup 14 ms (startup is not per-request CPU).

Reproduce from `worker/`:

```sh
npm ci
npm run typecheck
npm test
npm run build
node test/browser/run.mjs
```

## Initial migration public environment and acceptance

- Worker: `jason-passkey-auth-beta`; origin/RP: `https://auth.jasonstu.cc` / `auth.jasonstu.cc`.
- Final deployed version: `57286597-6481-4acc-80cf-c8c4ff7d3d93`. The last upload contains formatting-only changes after the optimized browser-tested version `46b06898-5c08-4197-8acb-9048f6686f11`.
- D1: `jason-passkey-auth-beta`, `ef061c6c-a56b-4837-9740-e8efed4f0524`, APAC primary observed in KIX, read replication disabled. `0001_native_auth.sql` and its `d1_migrations` record are applied. No production or PPQ database was rebuilt.
- Cloudflare MCP handled scoped resource discovery/configuration, custom-domain attachment, verification, exact test cleanup and aggregate analytics. Wrangler handled artifact upload and versioned migration/secret installation.
- Public browser runs passed at **05:13:00–05:13:48 UTC** and **05:22:56–05:23:44 UTC**. Both covered trusted UV administrator recovery, all Management views on desktop/mobile, CSV, registration gate, OAuth signup/login/existing-signup with PKCE and stable subjects, and ordinary-user Management denial.
- Both runs had zero JavaScript exceptions, zero 5xx responses and zero browser telemetry requests. A separate deployed smoke check confirmed public home/discovery, anonymous `/api/me`, unauthorized Management and no anonymous session cookie.
- The local system resolver retained a negative result for the newly created hostname. The browser test explicitly used validated Cloudflare DoH answers scoped to this process and this hostname. Requests retained the real public HTTPS URL, certificate verification, Host and WebAuthn Origin. No proxy, localhost bridge, certificate bypass or system network change was used. Ordinary system-DNS resolution on this Mac remains unverified.
- All four synthetic identities across the two runs, their credentials/sessions, recovery grants, temporary OAuth clients and related test history were removed using exact recorded identity predicates. D1 verified zero remaining users, credentials, sessions, grants, login/audit history and telemetry events; only the intentional `passkey-demo` client remains. Public registration is restored to **closed**. Private cleanup manifests are marked verified and consumed local test credentials were removed.
- Workers Logs/logpush and browser telemetry remain off. No Access configuration was changed or temporarily relaxed.

## Measured resource envelope

Cloudflare GraphQL aggregate analytics were read without enabling browser telemetry or authentication request logs. These are small adaptive analytics samples, not a controlled benchmark or a billing guarantee; analytics can arrive later. CPU fields are reported in microseconds and converted below.

| Window (UTC) | Successful invocations observed | CPU P50 | CPU P95 | CPU P99 | Worker errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| 05:13:00–05:14:00, original overview | 40 | 3.268 ms | 8.411 ms | 11.326 ms | 0 |
| 05:22:50–05:24:00, indexed overview count | 223 | 0.730 ms | 7.799 ms | 11.900 ms | 0 |

The first window also reported one client-disconnected invocation, with no Worker error. Management overview now uses one indexed 24-hour telemetry count instead of six full statistics queries; the complete telemetry page and collection-off history remain available. Different invocation mixes mean these quantiles do **not** establish a causal speedup.

The D1 snapshots for those windows reported respectively 407 / 125 rows read and 204 / 40 rows written; the database occupied 299,008 bytes after cleanup. These small-window counts can lag and must not be treated as a reliable per-user forecast. For scale only, repeating the larger observed row counts 50 times/day would be 20,350 reads and 10,200 writes/day; 50 × 223 invocations would be 11,150 requests/day. Real history growth, idle Management channels, enabled telemetry and other applications sharing account allowances change these figures.

Current documented Free limits are 100,000 Worker requests/day, **10 ms CPU/invocation**, 5 million D1 rows read/day, 100,000 rows written/day and 5 GB D1 storage. Request/row/storage observations leave substantial volume headroom for tens of active users, but **Free-tier reliability is not fully verified: measured P99 exceeds 10 ms**. Cloudflare permits occasional CPU bursts, but sustained over-limit execution may be terminated. We did not remove functionality, weaken authentication, enable a paid plan or purchase capacity to hide this boundary. The account billing/subscription read was permission-denied, so its plan cannot be independently certified here. The supported paid alternative is Workers Standard; check the account's current subscription and official pricing before choosing it.

Sources: [Workers limits and CPU flexibility](https://developers.cloudflare.com/workers/platform/limits/), [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/), [D1 pricing](https://developers.cloudflare.com/d1/platform/pricing/).

## Remaining acceptance and operator steps

- The operator has since created the real administrator. Do not repeat initialization or rebuild its data. Additional trusted recovery, if required, uses `npm run operator -- recovery --origin https://auth.jasonstu.cc --remote` from `worker/`; the one-use URL is saved to a private 0600 file, not printed or committed.
- Then create consuming applications' real OAuth clients and enable public registration only when desired. Existing test clients/identities are intentionally not migrated. The built-in demo client is initialized; no real application client is provisioned implicitly.
- Verify a real hardware/platform authenticator on the target Safari/iCloud/Android devices. Chromium virtual authenticators establish protocol/browser behavior, not every physical device combination.
- Optional external Jason/custom telemetry was tested with local protocol fixtures, including pairing and failure/concurrency behavior. No unrelated live telemetry service was reconfigured. The production default remains off.
- The cron handler has native workerd/D1 coverage, but the first real scheduled cloud execution has not yet occurred. Long-duration operation, sustained cold-start CPU and populated-account Free limits remain unverified.

This is a major runtime replacement, delivered for review through a PR. It is not automatically merged into `main`, and the open earlier PR is not automatically merged or closed.

## 2026-10-03 — Multiple-Passkey follow-up

- **109 Worker tests** and `npm run typecheck` passed. The local browser suite passed with **34 screenshots**, covering desktop/mobile Passkeys dialogs, additional-credential enrollment while registration is closed, inline UV reauthentication, cancelled enrollment, a second virtual USB authenticator, stable account/OAuth identity, and administrator operations on an individual credential. The first credential continued to sign in after the second was disabled or deleted.
- The browser suite also reproduces network timing explicitly: the real SSE response is delayed by **600 ms**, and the first real ACK response is held while a management write is requested. Before the fix this produced `409 channel_signature_invalid`; after the fix the ACK returned **200**, no write was sent before its response, and subsequent signed management writes succeeded. Native SSE now reads the challenge without rotating it; successful ACKs rotate the nonce atomically, and the browser serializes ACKs and management writes. Run this regression with `PASSKEY_BROWSER_DELAY_CHANNEL=1 node test/browser/run.mjs` from `worker/`.
- **R3 deployed browser acceptance passed** on version `8557cc9a-f157-4eff-9c60-8d6e58e9be48`, from **15:18:42.305 to 15:20:08.592 UTC**. Two scoped synthetic accounts exercised recovery, explicit security-key creation with required UV and a nonempty account display name, independent-device login with the same account ID/subject, cancellation, desktop/mobile layout, and precise disable/enable/delete operations. All three credential-management writes returned **200**. Disabled/deleted credentials were rejected while the first credential remained usable. The run recorded **zero channel errors, zero acceptance failures, zero JavaScript exceptions, zero 5xx responses and zero browser telemetry requests**.
- This run used working **system DNS** and the real `https://auth.jasonstu.cc` origin, with normal certificate verification. No proxy, URL rewriting, local bridge or system network change was used. Public registration remained **closed** throughout; only the two synthetic accounts were selected for mutations.
- **R3 cleanup verified through Cloudflare MCP.** No rows remain for the run's synthetic users, credentials, sessions, recovery grants, login history or audit history. The original account identity and active credential match the protected baseline; administrator/login permissions remain enabled and public registration remains **closed**. The private manifest is marked `cleanupPending: false` and `cleanupVerified: true`; the consumed local grant file was removed.
- **Physical Safari + YubiKey 5C enrollment has not passed acceptance.** Safari Technology Preview's authentication process returned `CTAP 0x03` (invalid message/item length) during `makeCredential`, before a PIN prompt. Read-only `getInfo` checks showed the PIN retry count unchanged at eight; the inspected excluded credential ID was 20 bytes, below the advertised 128-byte maximum. The root cause remains unconfirmed. Successful Chromium virtual USB authentication does not establish compatibility with that physical browser/device combination or a fix for this failure.

The measured resource envelope and **10 ms Free-tier CPU boundary** above remain applicable. This follow-up adds functional and concurrency evidence; it did not collect a new CPU benchmark or resolve the earlier P99 uncertainty.
