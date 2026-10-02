# Python Workers feasibility result — 2026-10-03

The original Flask application can be adapted to Python Workers, but this measured
version is unsuitable for a promise of stable operation within Workers Free's
10 ms CPU allowance. The production route therefore retains native Python on an
existing Linux host, behind Cloudflare; PPQ uses Workers and D1 independently.

A dedicated, temporary Worker loaded Flask 3.1.3, py_webauthn 2.8.0 and cryptography
47.0.0 under Pyodide, rendered the unmodified provider Jinja templates and original
CSS, generated options through the original `webauthn_service`, and executed a real
D1 `SELECT 41 + 1` using `run_sync`. All returned HTTP 200. It contained no accounts,
authentication endpoints, management routes or production secrets. Its only D1 was
a separate empty probe database; the production auth database was not accessed.

Measured remote CPU from Wrangler tail (milliseconds):

| Operation | Repeated requests |
| --- | --- |
| Original provider template render | 196, 158, 120 |
| WebAuthn options and one D1 read | 212, 102, 216 |
| Two WebCrypto PBKDF2 operations at 100,000 rounds | 227, 221, 202 |
| Two Python cryptography PBKDF2 operations at 100,000 rounds | 359 |

The first native Python probe at the original 120,000 rounds consumed 454 ms CPU.
These are remote `cpuTime` measurements, not network latency. Requests temporarily
returning 200 do not establish compliance with the free steady-state limit. Python
`perf_counter()` returned zero elapsed time remotely during pure computation, so it
was not used as a CPU measure.

Other concrete differences: Pyodide's `hashlib.pbkdf2_hmac` is absent. The equivalent
`cryptography` KDF works, while remote WebCrypto rejects more than 100,000 rounds
(the local workerd build accepted 120,000). The 100,000-round experiment was only a
probe; no production password derivation or OAuth digest behavior was weakened.
Workers D1 values are automatically converted to Python dictionaries by the current
SDK, and synchronous Flask handlers can bridge promises with `pyodide.ffi.run_sync`.
This bridge does not preserve a SQLite context manager transaction: registration,
recovery and one-use grants require an atomic D1 batch with SQL guards. A loop of
individual D1 `execute` calls is not an equivalent storage implementation.

The temporary Worker and its D1 database were deleted after the test. No custom
domain was attached. No Python Worker authentication service was published.

References: [Flask on Workers](https://developers.cloudflare.com/workers/languages/python/packages/flask/),
[Python packages](https://developers.cloudflare.com/workers/languages/python/packages/),
[D1 batch semantics](https://developers.cloudflare.com/d1/worker-api/d1-database/),
[Workers CPU limits](https://developers.cloudflare.com/workers/platform/limits/#cpu-time).
