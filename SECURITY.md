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

There is currently no paid bug bounty program.

## Supported Versions

Security fixes are developed against the current default branch and, when
practical, included in the next tagged release.

| Version | Supported |
| --- | --- |
| Current `main` branch | Yes |
| Latest tagged release | Best effort |
| Older releases and development snapshots | No |

Before reporting an issue, please verify whether it is reproducible on the current
`main` branch. Do not disclose secrets, credentials, private keys, session data,
access tokens, recovery tokens, or personal information in any report.

## Reporting a Vulnerability

Public GitHub issues are welcome for security observations, hardening ideas,
design questions, and findings that do not expose sensitive data or provide an
immediately usable exploit. Open discussion can help contributors compare
approaches, improve the security model, and develop fixes together.

Use this repository's
[private vulnerability reporting](https://github.com/jasonhejiahuan/Passkey-Auth/security/advisories/new)
channel when a report includes:

- A working exploit against a supported version.
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
the issue materially affects users of a supported version. Credit will be offered
when desired, but may be omitted at the reporter's request.
