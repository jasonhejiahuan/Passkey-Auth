# Security Policy

## Project Context

Passkey-Auth is an independently maintained open-source research and engineering
project focused on Passkeys, WebAuthn, OAuth, and passwordless authentication. It
is not a commercial identity service, a managed security product, or a substitute
for an organization-specific security review.

The project welcomes careful security research and constructive technical
discussion. Maintainer capacity is limited, so investigation and remediation are
handled on a best-effort basis. Reports that include clear reproduction steps,
impact analysis, and a practical remediation direction are especially helpful.

There is currently no formal bug bounty program.

## Project Versions

Passkey-Auth evolves quickly as a research and learning project. Releases,
development snapshots, and the default branch may differ substantially over
time, and the project does not maintain a fixed version-support schedule.

When reporting an issue, identify the tested commit, tag, or release and note
whether the behavior is also present in the current code when practical. This
helps maintainers understand the relevant implementation without implying a
long-term maintenance commitment for a particular version.

Do not disclose secrets, credentials, private keys, session data, access tokens,
recovery tokens, or personal information in any report.

## Reporting a Vulnerability

Public GitHub issues are welcome for security observations, hardening ideas,
design questions, and findings that do not expose sensitive data or provide an
immediately usable exploit. Open discussion can help contributors compare
approaches, improve the security model, and develop fixes together.

Use this repository's
[private vulnerability reporting](https://github.com/jasonhejiahuan/Passkey-Auth/security/advisories/new)
channel when a report includes:

- A working exploit with meaningful impact on the project.
- Authentication bypass or unauthorized access with meaningful impact.
- Credentials, tokens, personal data, or details from a real deployment.
- Information that would place users at avoidable risk if published before a fix.

To submit a private report:

1. Open the repository's **Security** page.
2. Select **Advisories**.
3. Select **Report a vulnerability**.
4. Submit the report with enough information for the maintainers to reproduce and
   assess the issue.

The report and subsequent discussion will remain private to the reporter and the
repository's security collaborators until disclosure is coordinated.

If you are unsure which channel to use, start with a private report. The
maintainers and reporter can later move the discussion into a public issue when
the sensitive details have been addressed.

## What to Include

A useful report should include:

- A concise title and description of the vulnerability.
- The affected commit, release, route, component, or configuration.
- Required preconditions and the assumed attacker capabilities.
- Reproduction steps or a minimal proof of concept.
- The expected behavior and the observed behavior.
- The potential confidentiality, integrity, or availability impact.
- Whether Passkey, WebAuthn, OAuth, session, CSRF, action-token, recovery, or
  management boundaries are crossed.
- Any known mitigations or suggested fixes.
- Your preferred name or handle for acknowledgment, if any.

Please keep proofs of concept narrowly scoped. Redact all tokens, cookies,
credential identifiers, user information, hostnames, IP addresses, and other
sensitive values.

## Areas of Interest

Good-faith research and independent review are welcome. Security topics of
particular interest include:

- Authentication or authorization bypasses.
- WebAuthn challenge, origin, RP ID, user-handle, or credential-binding flaws.
- OAuth state, redirect URI, authorization-code, or client-binding weaknesses.
- Session fixation, session invalidation, CSRF, or action-token replay issues.
- Privilege escalation or Management API access-control bypasses.
- Recovery-token, secret, access-token, or sensitive-data exposure.
- Injection, path traversal, unsafe deserialization, or server-side request
  forgery.
- Security-relevant cryptographic misuse.
- Vulnerable dependencies with a demonstrated impact on this project.

## Telemetry Data

Browser telemetry is disabled by default. Built-in mode uses a separate SQLite
database; external modes use a lazy-loaded jason-telemetry or custom HTTP
adapter and do not duplicate events into the local database.
Collection requests require a short-lived signed token bound to the current
in-memory policy and feature set. The token is collection authorization only; it
is never accepted as login, OAuth, Management, or identity proof.

The collector does not persist raw IP addresses or create a stable browser
fingerprint. It stores a keyed IP hash, coarse browser/device labels, the
administrator-selected signals, and the authenticated user ID when one is
already present in the Passkey-Auth session. Font, battery, hardware, and
network signals can increase identifiability and should be enabled only with an
appropriate notice, retention period, and legal basis for the deployment.

Management telemetry writes retain the normal admin session, CSRF, recent
Passkey reauthentication, and rotating action-token requirements. Treat
telemetry exports, the telemetry SQLite database, external endpoint
configuration, and external API credentials as sensitive operational data.
External credentials are never returned by Management APIs or inserted into
browser HTML. Browser-direct jason-telemetry delivery receives only a one-time
collection URL. Custom browser-direct delivery cannot use private Bearer/header
credentials; authenticated custom endpoints must use server relay.

When the browser supports it, the Management UI also opens a same-origin
Server-Sent Events channel and binds the current page to a temporary P-256
WebCrypto key. The channel exchanges signed ACKs, page visibility, and network
hints so the server can reject replayed Management writes after the channel is
active and stretch the interval for background or constrained clients. This
channel is only an additional page-possession signal; it is never accepted in
place of Passkey authentication, CSRF, the admin session, or the rotating
action token.

Jason Telemetry v13 automatic pairing uses a short-lived, one-use pairing code,
two independent nonces, and HMAC challenge-response. Pairing requires HTTPS
except on loopback. The generated API key is returned once over the server-to-
server connection and is never returned to the administrator's browser.

Please conduct testing only on code, accounts, and systems you own or are
explicitly authorized to assess. If testing unexpectedly exposes sensitive data,
stop and report the issue privately with only the minimum evidence required.

## Disclosure and Response

After receiving a report, the maintainers will aim to:

1. Acknowledge the report when maintenance availability permits.
2. Reproduce the issue and assess its impact and affected versions.
3. Discuss mitigations or a fix privately with the reporter.
4. Prepare a patch, tests, and documentation where appropriate.
5. Coordinate public disclosure after a fix or practical mitigation is available.

Response and remediation times vary with severity, reproducibility, project
capacity, and the complexity of the affected authentication flow. Please allow
reasonable time for investigation before publishing details. If circumstances
require earlier disclosure, discuss the proposed timeline in the private report.

The maintainers may publish a GitHub Security Advisory and may request a CVE when
the issue has meaningful impact on users or the wider ecosystem. Credit will be
offered when desired, but may be omitted at the reporter's request.
