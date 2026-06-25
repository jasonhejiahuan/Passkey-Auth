from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from ..storage import TelemetrySettings


def pair(
    *,
    base_url: str,
    pairing_code: str,
    timeout_seconds: float,
) -> dict:
    base_url = base_url.rstrip("/")
    code = str(pairing_code or "").strip()
    if not base_url or not code:
        raise ValueError("Jason Telemetry 地址和一次性配对码不能为空")
    client_nonce = secrets.token_urlsafe(24)
    request_proof = _proof(
        code,
        f"passkey-auth-pairing-request-v1:{client_nonce}",
    )
    challenge = _json_request(
        f"{base_url}/v13/integrations/passkey-auth/pairing/challenge",
        method="POST",
        payload={
            "client_nonce": client_nonce,
            "proof": request_proof,
        },
        timeout=timeout_seconds,
    )
    challenge_id = str(challenge.get("challenge_id") or "")
    server_nonce = str(challenge.get("server_nonce") or "")
    if not challenge_id or not server_nonce:
        raise RuntimeError("telemetry_invalid_pairing_challenge")
    complete_proof = _proof(
        code,
        (
            "passkey-auth-pairing-complete-v1:"
            f"{challenge_id}:{client_nonce}:{server_nonce}"
        ),
    )
    response = _json_request(
        f"{base_url}/v13/integrations/passkey-auth/pairing/complete",
        method="POST",
        payload={
            "challenge_id": challenge_id,
            "client_nonce": client_nonce,
            "proof": complete_proof,
            "client": {
                "name": "Passkey-Auth",
                "integration_version": 1,
            },
        },
        timeout=timeout_seconds,
    )
    return {
        "apiKey": str(response.get("api_key") or ""),
        "serverVersion": response.get("server_version"),
    }


class Sender:
    def __init__(self, settings: TelemetrySettings):
        self._base_url = settings.jason_base_url.rstrip("/")
        self._api_key = settings.jason_api_key
        self._timeout = settings.timeout_seconds
        key = quote(self._api_key, safe="")
        self._telemetry_url = f"{self._base_url}/v12/{key}/telemetry"
        self._status_url = f"{self._base_url}/v12/{key}/status"
        self._token_url = (
            f"{self._base_url}/v12/{key}/browser-collection-token"
        )

    def send(self, event: dict) -> None:
        _json_request(
            self._telemetry_url,
            method="POST",
            payload=event,
            timeout=self._timeout,
        )

    def test(self) -> None:
        _json_request(
            self._status_url,
            method="GET",
            payload=None,
            timeout=self._timeout,
        )

    def create_direct_target(self, metadata: dict) -> dict:
        response = _json_request(
            self._token_url,
            method="POST",
            payload=metadata,
            timeout=self._timeout,
        )
        token = str(response.get("token") or "")
        if not token:
            raise RuntimeError("telemetry_invalid_token_response")
        target = (
            f"{self._base_url}/v12/browser/{quote(token, safe='')}"
            "/device-info-submit"
        )
        return {
            "url": target,
            "headers": {},
            "contentType": "text/plain;charset=UTF-8",
            "opaque": True,
        }


def _json_request(
    url: str,
    *,
    method: str,
    payload: dict | None,
    timeout: float,
) -> dict:
    body = (
        json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
        if payload is not None
        else None
    )
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = Request(url, data=body, headers=headers, method=method)
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read(65_536)
    except HTTPError as error:
        raise RuntimeError(f"telemetry_http_{error.code}") from None
    except (URLError, TimeoutError, OSError):
        raise RuntimeError("telemetry_unavailable") from None
    if not raw:
        return {}
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise RuntimeError("telemetry_invalid_response") from None
    if not isinstance(value, dict):
        raise RuntimeError("telemetry_invalid_response")
    return value


def _proof(code: str, message: str) -> str:
    return hmac.new(
        code.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
