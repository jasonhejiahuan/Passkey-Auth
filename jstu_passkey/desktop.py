from __future__ import annotations

import os
import secrets
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path


def application_data_dir() -> Path:
    if sys.platform == "win32":
        root = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        root = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return root / "Passkey-Auth"


def configure_desktop_environment(data_dir: Path | None = None) -> Path:
    target = data_dir or application_data_dir()
    target.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("PASSKEY_DATABASE", str(target / "passkeys-v2.sqlite3"))
    os.environ.setdefault(
        "PASSKEY_TELEMETRY_DATABASE",
        str(target / "passkeys-telemetry-v1.sqlite3"),
    )
    if not os.environ.get("FLASK_SECRET_KEY"):
        os.environ["FLASK_SECRET_KEY"] = _persistent_secret(target / "flask-secret")
    os.environ.setdefault("HOST", "127.0.0.1")
    os.environ.setdefault("PORT", "5003")
    os.environ.setdefault("PASSKEY_ORIGIN", f"http://localhost:{os.environ['PORT']}")
    return target


def _persistent_secret(path: Path) -> str:
    if path.exists():
        value = path.read_text(encoding="utf-8").strip()
        if len(value) >= 32:
            return value

    value = secrets.token_hex(32)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return path.read_text(encoding="utf-8").strip()
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(value)
    return value


def _open_browser_when_ready(host: str, port: int, path: str = "/") -> None:
    browser_host = (
        "localhost"
        if host in {"127.0.0.1", "0.0.0.0", "::", "::1"}
        else host
    )
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((browser_host, port), timeout=0.5):
                webbrowser.open(f"http://{browser_host}:{port}{path}")
                return
        except OSError:
            time.sleep(0.25)


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    configure_desktop_environment()
    host = os.environ["HOST"]
    port = int(os.environ["PORT"])
    browser_path = "/"
    if "--reregister-admin" in arguments:
        index = arguments.index("--reregister-admin")
        if index + 1 < len(arguments):
            browser_path = f"/{arguments[index + 1]}"
    threading.Thread(
        target=_open_browser_when_ready,
        args=(host, port, browser_path),
        daemon=True,
    ).start()

    from .app import main as run_server

    return run_server(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
