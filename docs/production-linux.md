> Retired deployment path. The supported server is now the [native Cloudflare Worker](cloudflare-native.md). This file is retained only as historical evidence, not an installation guide.

# Isolated Linux service

The provider keeps its original Flask routes, SQLite transactions and Jason-Passkey UI.
PPQ runs separately on Cloudflare Workers and D1. This deployment does not replace an
existing provider or any listener on port 5003. The dedicated upstream is
`127.0.0.1:5013`; the public origin and RP ID are `https://auth.jasonstu.cc` and
`auth.jasonstu.cc`. Choose these before creating real Passkeys.

Use an immutable release under `/opt/jason-passkey-auth/releases/<commit>` and an
atomic `current` symlink. Install `requirements-production.txt` into that release's
`.venv`. It pins the Linux service dependencies, including cryptography 50.0.2; the
desktop requirements remain separate. Application releases are read-only to the
service user. Keep SQLite files outside releases.

Create the non-login service user `jason-passkey-auth` and private directories
`/var/lib/jason-passkey-auth` and `/etc/jason-passkey-auth`, owned by that user with
mode 0700. Provision as that user, from the release directory:

```sh
.venv/bin/python scripts/provision_service.py \
  --database /var/lib/jason-passkey-auth/auth-v2.sqlite3 \
  --environment /etc/jason-passkey-auth/service.env \
  --client-secret-file /etc/jason-passkey-auth/ppq-client-secret \
  --origin https://auth.jasonstu.cc \
  --redirect-uri https://ppq.beta.jasonstu.cc/api/auth/callback \
  --enable-registration
```

This creates no users. It writes cryptographically random signing and client
credentials only to mode-0600 files. Re-running preserves them; conflicting origins,
clients or file permissions stop provisioning. Without `--enable-registration`,
registration remains closed. The dedicated `ppq-practice` client is **not** a demo
client, and accepts exactly the supplied callback. The provider's internal demo
client remains separate. Do not substitute the default demo client for PPQ.

The environment file contains only these application settings: `FLASK_SECRET_KEY`,
`PASSKEY_DATABASE`, `PASSKEY_TELEMETRY_DATABASE`, `PASSKEY_ORIGIN`, `PASSKEY_RP_ID`,
`PASSKEY_RP_NAME`, `PASSKEY_REGISTRATION_ENABLED`, `PASSKEY_SECURE_COOKIES`,
`PASSKEY_TRUST_PROXY_HEADERS`, `PASSKEY_OAUTH_CLIENT_ID`, and
`PASSKEY_OAUTH_CLIENT_SECRET`. Do not source unreviewed arbitrary environment files.
Transfer `ppq-client-secret` through an authenticated administrative channel into a
protected local file, then supply its bytes to `wrangler secret put
PASSKEY_CLIENT_SECRET --env beta` through stdin. Never print the file. Configure
PPQ's public values as issuer `https://auth.jasonstu.cc` and client ID `ppq-practice`.

Install the unit in `deploy/jason-passkey-auth.service` after reviewing existing
services. It runs one Gunicorn process with four threads because provider runtime
settings and telemetry gates are cached in process. It does not expose a public
socket or Flask's development server. Check `systemctl status`, and request `/` and
`/.well-known/oauth-authorization-server` from the loopback listener with the real
Host header before enabling the public virtual host.

Nginx terminates HTTPS using a certificate valid for `auth.jasonstu.cc` and proxies
to port 5013. Cloudflare must use strict origin certificate validation. Set the
upstream `Host`, `X-Forwarded-Proto`, and `X-Forwarded-For` deliberately; never expose
the trusted-proxy upstream directly. Disable access logging for this auth virtual
host, as callback queries and one-use recovery paths can contain credentials.
Limit request bodies (for example 128 KiB) and prevent caching on all dynamic auth
routes. The existing original static assets can be served by Flask for this small
service; no UI rewrite is required. DNS/TLS and the existing nginx configuration
must be checked on the actual host before enabling the vhost.

## Administrator bootstrap

Normal registration always creates a non-admin user. After the owner registers with
a real Passkey, independently verify their provider `sub` (the stable user handle
returned by authenticated `/oauth/userinfo`). An operator with shell access can then
run the following as the service user:

```sh
.venv/bin/python scripts/grant_admin.py \
  --database /var/lib/jason-passkey-auth/auth-v2.sqlite3 \
  --subject VERIFIED_PROVIDER_SUB
```

The command rejects unknown/disabled identities, preserves existing demo permission,
and never selects the first account or trusts a display name. The user can then
authenticate freshly at `/management`. Provider admin and PPQ platform admin are
separate grants; ordinary practice remains available to both. The existing one-use
recovery ceremony is another operator-controlled option, but do not put a recovery
URL in chat, logs or screenshots.

## Backups and rollback

Schedule a daily backup using a dedicated systemd timer, and also back up before each release. Before replacing `current`, use Python's `sqlite3.Connection.backup()` to create an
online snapshot of the auth database and, when present, the telemetry database.
Do not copy a live SQLite file with `cp`. Write snapshots under a private timestamped
directory in `/var/backups/jason-passkey-auth`, verify `PRAGMA integrity_check`
on each snapshot, and protect the environment/PPQ secret backups separately with
the same access restrictions. Keep an off-host encrypted copy using the host's
existing backup policy; do not invent a new external destination.

Rollback switches `current` to the previous known release and restarts this service
only. It does not erase account data, rotate signing keys, or modify the old 5003
service. Restore database snapshots only as an explicit data-recovery operation,
since restoring them can discard newly registered accounts and replay consumed
one-time state. Verify a real Passkey login, code exchange, userinfo and PPQ return
at the final HTTPS origins after release; loopback success alone is insufficient.

The included `scripts/backup_service.py` and `deploy/jason-auth-backup.*` units implement a daily online backup for the auth database with 14 retained copies. Install the script as `/usr/local/sbin/backup-jason-auth.py`; the destination is root-owned and mode 0700. The separate telemetry database is currently disabled and requires extending the backup job if it is enabled. `deploy/nginx-auth.conf` is the TLS virtual-host template; enable it only after the named certificate exists. Its Cloudflare real-IP ranges were obtained from Cloudflare on 3 October 2026 and apply only to this virtual host.
