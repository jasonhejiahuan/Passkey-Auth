"""Provision an isolated service and confidential PPQ client; never print secrets."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import sys
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from jstu_passkey.storage import PasskeyStore


def private_write(path: Path, text: str) -> None:
    if path.is_symlink():
        raise ValueError("Refusing a symlink at a protected file path")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(text)


def private_read(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError("Existing protected files must be regular files with mode 0600")
    return path.read_text()


def provision(*, database: Path, environment: Path, client_secret_file: Path,
              origin: str, redirect_uri: str, client_id: str = "ppq-practice",
              enable_registration: bool = False) -> dict:
    public_origin = urlsplit(origin)
    callback = urlsplit(redirect_uri)
    if (public_origin.scheme != "https" or not public_origin.hostname
            or public_origin.username or public_origin.password or public_origin.port
            or public_origin.path not in {"", "/"} or public_origin.query or public_origin.fragment):
        raise ValueError("Origin must be an exact HTTPS origin")
    if (callback.scheme != "https" or not callback.hostname or callback.username
            or callback.password or callback.fragment or callback.query):
        raise ValueError("Callback must be one exact HTTPS URL without a query or fragment")
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", client_id):
        raise ValueError("Invalid client ID")
    for path in (database, environment, client_secret_file):
        if not path.is_absolute() or not path.parent.is_dir() or path.is_symlink():
            raise ValueError("Use absolute paths inside pre-created private service directories")
        if any(character in str(path) for character in "\r\n\"'"):
            raise ValueError("Service paths cannot contain quotes or newlines")
    origin = f"https://{public_origin.hostname}"
    existing_env = {}
    if environment.exists():
        existing_env = dict(line.split("=", 1) for line in private_read(environment).splitlines() if line and not line.startswith("#"))
        expected = {"PASSKEY_DATABASE": str(database), "PASSKEY_ORIGIN": origin,
                    "PASSKEY_RP_ID": public_origin.hostname}
        if any(existing_env.get(key) != value for key, value in expected.items()):
            raise ValueError("Existing service configuration belongs to a different database or origin")
    if client_secret_file.exists():
        client_secret = private_read(client_secret_file).strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", client_secret):
            raise ValueError("Existing PPQ secret has an unsupported format")
    else:
        client_secret = secrets.token_urlsafe(48)
        private_write(client_secret_file, client_secret + "\n")

    previous_umask = os.umask(0o077)
    try:
        store = PasskeyStore(database)
        client = store.get_oauth_client(client_id)
        if client:
            if client.is_demo or not store.verify_oauth_client_secret(client_id, client_secret):
                raise ValueError("Existing client conflicts with the protected PPQ credential")
            if client.redirect_uris != [redirect_uri] or not client.enabled:
                raise ValueError("Existing PPQ client settings differ; review them before provisioning")
        else:
            store.create_oauth_client(client_id=client_id, name="PPQ Practice Lab",
                                      client_secret=client_secret, redirect_uris=[redirect_uri], is_demo=False)
        if enable_registration:
            store.set_registration_settings(mode="open", enabled_until=None, default_demo_allowed=False)
        if not environment.exists():
            values = {
                "FLASK_SECRET_KEY": secrets.token_urlsafe(64),
                "PASSKEY_DATABASE": str(database),
                "PASSKEY_TELEMETRY_DATABASE": str(database.with_name("telemetry-v1.sqlite3")),
                "PASSKEY_ORIGIN": origin,
                "PASSKEY_RP_ID": public_origin.hostname,
                "PASSKEY_RP_NAME": "Jason-Passkey",
                "PASSKEY_REGISTRATION_ENABLED": "false",
                "PASSKEY_SECURE_COOKIES": "true",
                "PASSKEY_TRUST_PROXY_HEADERS": "true",
                "PASSKEY_OAUTH_CLIENT_ID": "jason-passkey-internal-demo",
                "PASSKEY_OAUTH_CLIENT_SECRET": secrets.token_urlsafe(48),
            }
            private_write(environment, "".join(f"{key}={value}\n" for key, value in values.items()))
    finally:
        os.umask(previous_umask)
    return {"issuer": origin, "clientId": client_id, "redirectUri": redirect_uri,
            "secretFile": str(client_secret_file), "environmentFile": str(environment),
            "database": str(database)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--environment", type=Path, required=True)
    parser.add_argument("--client-secret-file", type=Path, required=True)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--redirect-uri", required=True)
    parser.add_argument("--client-id", default="ppq-practice")
    parser.add_argument("--enable-registration", action="store_true")
    args = parser.parse_args()
    try:
        result = provision(**vars(args))
    except (ValueError, OSError) as error:
        # Validation messages contain no credential values.
        print(f"Provisioning failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
