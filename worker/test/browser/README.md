# Browser acceptance

Run from `worker/` after `npm ci` and `node scripts/build-assets.mjs`:

```sh
node test/browser/run.mjs
```

The run uses installed Chrome, a local workerd instance, an isolated temporary D1 database and Chromium's virtual Passkey authenticators. It never connects to a deployed provider or uses an existing browser profile. All test users, credentials and database files are removed in `finally`.

To retain screenshots, set `PASSKEY_BROWSER_ARTIFACTS` to an output directory outside the repository. Screenshots cover desktop/mobile public pages and all original management views, including dark appearance. They contain synthetic identities only. No OAuth code, token, recovery URL, raw credential or client secret is printed.

The local run also applies every numbered migration, selects the security-key option and adds a second virtual USB device to an existing account while public registration is closed, and proves both devices retain the same account and OAuth subject. It exercises expired-UV inline reauthentication, cancelled enrollment with no new credential, desktop/mobile Passkeys dialogs, and administrator disable/enable/delete of only the second key. It checks that the first key still signs in and the administrator's own key is unchanged. A separate expired-UV check inside management cancels enrollment, then performs a signed management write to catch stale action-token or channel handling. The run also covers a fresh recovery administrator's first management write after a reload, with long synthetic usernames on mobile. Set `PASSKEY_BROWSER_DELAY_CHANNEL=1` to delay delivery of the real SSE challenge response by 600 ms, hold the first real acknowledgement response while the user requests a write, and prove that the write waits for the acknowledgement; no response or authentication proof is mocked.

`pages.test.ts` separately compares 21 original Python-rendered HTML fixtures using synthetic values and verifies that all static assets and the lazy registration module remain byte-identical. Two link-demo fixtures include the new invisible CSRF input used for form submissions under the retained `no-referrer` policy. `pages.worker.test.ts` proves precompiled template execution inside workerd. The only result-page content change is redaction of authentication secrets in the original debug sections.

## Explicit remote beta run

`remote.mjs` is separate and never runs as part of the local suite. An operator supplies `PASSKEY_REMOTE_ORIGIN`, `PASSKEY_REMOTE_RECOVERY_FILE`, `PASSKEY_REMOTE_CLIENT_FILE` and a new `PASSKEY_REMOTE_MANIFEST` path. The credential JSON files must be private (0600). Recovery accepts the operator command's `{ "url": ... }` output; the client file contains `clientId`, `clientSecret` and `redirectUri` (or `redirectUris`). Its exact callback must be `/test/browser/callback` on the same beta origin. Browser interception prevents a request reaching another application.

Registration must already be open and telemetry off for this test. The script does not change global settings. It creates two unique, randomly prefixed test users, records each intended username before registration and stores the resulting IDs, subjects and hashed session identifiers in a private manifest. It never captures screenshots or prints URLs, credential material, exception messages or response bodies.

If a newly created beta hostname is still negatively cached by system DNS, explicitly set `PASSKEY_REMOTE_RESOLVER=cloudflare-doh`. The runner validates Cloudflare DoH's question and exact-host IPv4 answers, then applies a single-host Chrome resolver rule and a single-host Node process lookup override. Other hosts retain normal resolution. The original HTTPS URL, TLS certificate validation, Host and WebAuthn Origin remain unchanged. No proxy, local bridge, system DNS change or certificate bypass is used. The manifest records the selected resolver; process overrides are restored on exit.

Run `node test/browser/remote.mjs` only after the operator has prepared scoped test credentials. Both success and failure leave `cleanupPending: true` in the manifest: the operator must delete the exact recorded test identities and related state, then verify absence before clearing that flag. Closing the browser is not remote database cleanup. The script will not overwrite an existing manifest.

## Explicit remote multiple-Passkeys run

`multiple-passkeys-remote.mjs` is a separate operator-invoked test, not part of `npm test` or the local run. It needs no OAuth client. Supply:

- `PASSKEY_REMOTE_ORIGIN`: the deployed HTTPS origin.
- `PASSKEY_REMOTE_RECOVERY_FILE`: a private regular JSON file (0600) with exactly two independent operator-created recovery grants, shaped as `{ "grants": [{ "url": "..." }, { "url": "..." }] }`. Each URL must belong to that origin. Do not put its values in shell arguments or logs.
- `PASSKEY_REMOTE_MANIFEST`: a new private manifest path; an existing file is never overwritten.
- Optional `PASSKEY_REMOTE_RESOLVER=cloudflare-doh`, with the same exact-host, process-only resolver behavior described above.

The operator must explicitly authorize and prepare both fresh grants before running `node test/browser/multiple-passkeys-remote.mjs`. Both grants create uniquely named synthetic administrators: A manages only B's second key, so no existing account is modified. Ordinary registration must remain closed; the test checks its state and never changes it. The security-key selection must request cross-platform attachment with the security-key hint, a nonempty account display name and required UV. A virtual USB authenticator completes creation and signs in from an independent browser context, and its account ID and subject must match B. Disabling or deleting it must reject that device while B's first device still signs in; enabling it must restore sign-in.

The run also checks cancelled enrollment, original management access to the Passkeys dialog, and desktop/mobile dialog fit. Raw virtual private keys are transferred only in process memory, never stored. This Chrome virtual-device test does not replace physical Safari/YubiKey validation. It captures no screenshots and prints no exception details, page content, tokens, URLs, or user data. Test usernames are recorded before creation; resulting user IDs, credential row IDs, grant hashes, session hashes, and each intended credential mutation are checkpointed to the private manifest. Safe diagnostic checkpoints contain only fixed stage names, method/status/category, whitelisted error names, and booleans/counts for synthetic-user controls. They never contain raw exception messages or page content. Local tests cover forced stale-session reauthentication and first management writes after recovery/reload; the remote test does not modify session rows.

Both success and failure leave `cleanupPending: true`. The operator must remove only the manifest's test identities and related rows, verify their absence and confirm that the original account/credentials and registration setting remain unchanged. Do not reuse a consumed grant or automatically retry a failed run. Closing browser contexts is not cloud database cleanup.
