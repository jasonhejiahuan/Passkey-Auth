from __future__ import annotations

import argparse
import ipaddress
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .desktop import application_data_dir


_HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def detect_lan_ip() -> str:
    """Return the address most likely to be reachable from the local network."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        except OSError:
            try:
                return socket.gethostbyname(socket.gethostname())
            except OSError:
                return "127.0.0.1"


def default_local_hostname() -> str:
    raw_hostname = (socket.gethostname() or socket.getfqdn() or "").strip().strip(".")
    if not raw_hostname or raw_hostname == "localhost" or is_ip_address(raw_hostname):
        raw_hostname = "passkey-auth"
    if raw_hostname.endswith(".local"):
        raw_hostname = raw_hostname[: -len(".local")]
    raw_hostname = raw_hostname.split(".", 1)[0]
    label = _domain_label(raw_hostname) or "passkey-auth"
    return f"{label}.local"


def default_origin(hostname: str, https_port: int) -> str:
    host = (
        f"[{hostname}]"
        if ":" in hostname and not hostname.startswith("[")
        else hostname
    )
    return f"https://{host}:{https_port}"


def is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return True


def _domain_label(value: str) -> str:
    label = re.sub(r"[^A-Za-z0-9-]+", "-", value).strip("-").lower()
    return label[:63].strip("-")


def origin_hostname(origin: str) -> str:
    parts = urlsplit(origin)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("origin must be an https URL with a host")
    if is_ip_address(parts.hostname):
        raise ValueError(
            "origin host must be a domain name for WebAuthn; use a .local hostname "
            "or a hosts/DNS name instead of a raw IP address"
        )
    return parts.hostname


def build_backend_environment(
    *,
    base_env: dict[str, str],
    origin: str,
    backend_port: int,
    backend_host: str,
) -> dict[str, str]:
    env = dict(base_env)
    env["HOST"] = backend_host
    env["PORT"] = str(backend_port)
    env["PASSKEY_ORIGIN"] = origin
    env.setdefault("PASSKEY_TRUST_PROXY_HEADERS", "true")
    env.setdefault("PASSKEY_SECURE_COOKIES", "true")
    env.setdefault("PASSKEY_HSTS_MAX_AGE_SECONDS", "0")
    env.setdefault("FLASK_DEBUG", "false")
    env.setdefault("PASSKEY_RP_ID", origin_hostname(origin))
    return env


def certificate_paths(cert_root: Path, hostname: str) -> tuple[Path, Path]:
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", hostname).strip("._") or "local"
    cert_dir = cert_root / safe_name
    return cert_dir / "cert.pem", cert_dir / "key.pem"


def ensure_self_signed_certificate(
    *,
    hostname: str,
    cert_root: Path | None = None,
) -> tuple[Path, Path]:
    root = cert_root or application_data_dir() / "local-https"
    cert_path, key_path = certificate_paths(root, hostname)
    if cert_path.exists() and key_path.exists():
        return cert_path, key_path

    openssl = shutil.which("openssl")
    if not openssl:
        raise RuntimeError(
            "openssl is required to create the local self-signed certificate"
        )

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    config_path = cert_path.parent / "openssl.cnf"
    config_path.write_text(_openssl_config(hostname), encoding="utf-8")
    command = [
        openssl,
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "825",
        "-keyout",
        str(key_path),
        "-out",
        str(cert_path),
        "-config",
        str(config_path),
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)
    try:
        key_path.chmod(0o600)
        cert_path.chmod(0o644)
    except OSError:
        pass
    return cert_path, key_path


def choose_origin(
    *,
    explicit_origin: str,
    env_origin: str,
    hostname: str,
    https_port: int,
) -> str:
    if explicit_origin:
        return explicit_origin
    if env_origin.startswith("https://"):
        return env_origin
    return default_origin(hostname, https_port)


def _openssl_config(hostname: str) -> str:
    san_entries = _subject_alt_names(hostname)
    alt_names = "\n".join(
        f"{kind}.{index} = {value}"
        for index, (kind, value) in enumerate(san_entries, start=1)
    )
    return f"""[req]
default_bits = 2048
prompt = no
distinguished_name = dn
x509_extensions = v3_req

[dn]
CN = {hostname}

[v3_req]
subjectAltName = @alt_names

[alt_names]
{alt_names}
"""


def _subject_alt_names(hostname: str) -> list[tuple[str, str]]:
    names: list[tuple[str, str]] = [("DNS", "localhost"), ("IP", "127.0.0.1")]
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        names.append(("DNS", hostname))
    else:
        names.append(("IP", hostname))
    return names


def run_proxy(
    *,
    bind_host: str,
    https_port: int,
    backend_host: str,
    backend_port: int,
    cert_path: Path,
    key_path: Path,
) -> None:
    handler = _proxy_handler(backend_host=backend_host, backend_port=backend_port)
    server = ThreadingHTTPServer((bind_host, https_port), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def _proxy_handler(*, backend_host: str, backend_port: int):
    class LocalHttpsProxyHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            self._proxy()

        def do_HEAD(self) -> None:
            self._proxy()

        def do_POST(self) -> None:
            self._proxy()

        def do_PUT(self) -> None:
            self._proxy()

        def do_PATCH(self) -> None:
            self._proxy()

        def do_DELETE(self) -> None:
            self._proxy()

        def do_OPTIONS(self) -> None:
            self._proxy()

        def log_message(self, format: str, *args) -> None:
            sys.stderr.write(f"[local-https] {self.address_string()} {format % args}\n")

        def _proxy(self) -> None:
            content_length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(content_length) if content_length else None
            url = f"http://{backend_host}:{backend_port}{self.path}"
            headers = _forward_headers(
                source_headers=dict(self.headers),
                client_ip=self.client_address[0],
                external_host=self.headers.get("Host", ""),
            )
            request = Request(url, data=body, headers=headers, method=self.command)
            try:
                with urlopen(request, timeout=30) as response:
                    payload = response.read()
                    self._send_response(
                        status=response.status,
                        reason=response.reason,
                        headers=dict(response.headers),
                        payload=payload,
                    )
            except HTTPError as error:
                payload = error.read()
                self._send_response(
                    status=error.code,
                    reason=error.reason,
                    headers=dict(error.headers),
                    payload=payload,
                )
            except (TimeoutError, URLError, OSError) as error:
                payload = f"Local HTTPS proxy could not reach backend: {error}".encode(
                    "utf-8"
                )
                self._send_response(
                    status=502,
                    reason="Bad Gateway",
                    headers={"Content-Type": "text/plain; charset=utf-8"},
                    payload=payload,
                )

        def _send_response(
            self,
            *,
            status: int,
            reason: str,
            headers: dict[str, str],
            payload: bytes,
        ) -> None:
            self.send_response(status, reason)
            for name, value in headers.items():
                if (
                    name.lower() in _HOP_BY_HOP_HEADERS
                    or name.lower() == "content-length"
                ):
                    continue
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

    return LocalHttpsProxyHandler


def _forward_headers(
    *,
    source_headers: dict[str, str],
    client_ip: str,
    external_host: str,
) -> dict[str, str]:
    headers = {
        name: value
        for name, value in source_headers.items()
        if name.lower() not in _HOP_BY_HOP_HEADERS and name.lower() != "host"
    }
    prior_for = headers.get("X-Forwarded-For")
    headers["X-Forwarded-For"] = f"{prior_for}, {client_ip}" if prior_for else client_ip
    headers["X-Forwarded-Proto"] = "https"
    headers["X-Forwarded-Host"] = external_host
    headers["Host"] = external_host
    return headers


def wait_for_backend(host: str, port: int, timeout_seconds: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m jstu_passkey.local_https_proxy",
        description="Run Passkey-Auth behind a local HTTPS reverse proxy.",
    )
    parser.add_argument("--https-port", type=int, default=5443)
    parser.add_argument("--backend-port", type=int, default=5003)
    parser.add_argument("--backend-host", default="127.0.0.1")
    parser.add_argument("--bind-host", default="0.0.0.0")
    parser.add_argument("--origin", default="")
    parser.add_argument("--cert", type=Path)
    parser.add_argument("--key", type=Path)
    parser.add_argument("--cert-root", type=Path)
    parser.add_argument("--reregister-admin", metavar="TOKEN")
    args = parser.parse_args(argv)

    env_origin = os.environ.get("PASSKEY_ORIGIN") or ""
    lan_ip = detect_lan_ip()
    if args.origin:
        origin = args.origin
    elif env_origin.startswith("https://"):
        origin = env_origin
    else:
        origin = choose_origin(
            explicit_origin="",
            env_origin=env_origin,
            hostname=default_local_hostname(),
            https_port=args.https_port,
        )
    try:
        hostname = origin_hostname(origin)
    except ValueError as error:
        parser.error(str(error))

    if args.cert and args.key:
        cert_path, key_path = args.cert, args.key
    elif args.cert or args.key:
        parser.error("--cert and --key must be provided together")
    else:
        try:
            cert_path, key_path = ensure_self_signed_certificate(
                hostname=hostname,
                cert_root=args.cert_root,
            )
        except (RuntimeError, subprocess.CalledProcessError) as error:
            print(f"Certificate setup failed: {error}", file=sys.stderr)
            return 2

    backend_env = build_backend_environment(
        base_env=dict(os.environ),
        origin=origin,
        backend_port=args.backend_port,
        backend_host=args.backend_host,
    )
    backend_args = [sys.executable, "-m", "jstu_passkey.app"]
    if args.reregister_admin:
        backend_args.extend(["--reregister-admin", args.reregister_admin])

    backend = subprocess.Popen(backend_args, env=backend_env)
    try:
        if not wait_for_backend(args.backend_host, args.backend_port):
            exit_code = backend.poll()
            if exit_code is not None:
                return int(exit_code)
            print(
                f"Backend did not become ready on {args.backend_host}:{args.backend_port}",
                file=sys.stderr,
            )
            return 1
        print(
            "\n".join(
                (
                    f"Passkey-Auth local HTTPS origin: {origin}",
                    f"Proxy: https://{args.bind_host}:{args.https_port} -> "
                    f"http://{args.backend_host}:{args.backend_port}",
                    f"Detected LAN IP: {lan_ip}",
                    f"Certificate: {cert_path}",
                    "Use the domain origin above for Passkey/WebAuthn; raw IP "
                    "origins are not valid RP IDs.",
                    "Your browser will warn because the certificate is self-signed.",
                )
            ),
            flush=True,
        )
        run_proxy(
            bind_host=args.bind_host,
            https_port=args.https_port,
            backend_host=args.backend_host,
            backend_port=args.backend_port,
            cert_path=cert_path,
            key_path=key_path,
        )
    except KeyboardInterrupt:
        return 0
    finally:
        backend.terminate()
        try:
            backend.wait(timeout=5)
        except subprocess.TimeoutExpired:
            backend.kill()
            backend.wait()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
