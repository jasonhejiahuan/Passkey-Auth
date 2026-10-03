# Browser acceptance

Run from `worker/` after `npm ci` and `node scripts/build-assets.mjs`:

```sh
node test/browser/run.mjs
```

The run uses installed Chrome, a local workerd instance, an isolated temporary D1 database and Chromium's virtual Passkey authenticator. It never connects to a deployed provider or uses an existing browser profile. All test users, credentials and database files are removed in `finally`.

To retain screenshots, set `PASSKEY_BROWSER_ARTIFACTS` to an output directory outside the repository. Screenshots cover desktop/mobile public pages and all original management views, including dark appearance. They contain synthetic identities only. No OAuth code, token, recovery URL, raw credential or client secret is printed.

`pages.test.ts` separately compares 21 original Python-rendered HTML fixtures using synthetic values and verifies that all static assets and the lazy registration module remain byte-identical. Two link-demo fixtures include the new invisible CSRF input used for form submissions under the retained `no-referrer` policy. `pages.worker.test.ts` proves precompiled template execution inside workerd. The only result-page content change is redaction of authentication secrets in the original debug sections.

## Explicit remote beta run

`remote.mjs` is separate and never runs as part of the local suite. An operator supplies `PASSKEY_REMOTE_ORIGIN`, `PASSKEY_REMOTE_RECOVERY_FILE`, `PASSKEY_REMOTE_CLIENT_FILE` and a new `PASSKEY_REMOTE_MANIFEST` path. The credential JSON files must be private (0600). Recovery accepts the operator command's `{ "url": ... }` output; the client file contains `clientId`, `clientSecret` and `redirectUri` (or `redirectUris`). Its exact callback must be `/test/browser/callback` on the same beta origin. Browser interception prevents a request reaching another application.

Registration must already be open and telemetry off for this test. The script does not change global settings. It creates two unique, randomly prefixed test users, records each intended username before registration and stores the resulting IDs, subjects and hashed session identifiers in a private manifest. It never captures screenshots or prints URLs, credential material, exception messages or response bodies.

If a newly created beta hostname is still negatively cached by system DNS, explicitly set `PASSKEY_REMOTE_RESOLVER=cloudflare-doh`. The runner validates Cloudflare DoH's question and exact-host IPv4 answers, then applies a single-host Chrome resolver rule and a single-host Node process lookup override. Other hosts retain normal resolution. The original HTTPS URL, TLS certificate validation, Host and WebAuthn Origin remain unchanged. No proxy, local bridge, system DNS change or certificate bypass is used. The manifest records the selected resolver; process overrides are restored on exit.

Run `node test/browser/remote.mjs` only after the operator has prepared scoped test credentials. Both success and failure leave `cleanupPending: true` in the manifest: the operator must delete the exact recorded test identities and related state, then verify absence before clearing that flag. Closing the browser is not remote database cleanup. The script will not overwrite an existing manifest.
