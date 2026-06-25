from __future__ import annotations

import json
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ..storage import TelemetrySettings


class Sender:
    def __init__(self, settings: TelemetrySettings):
        self._url = settings.custom_url
        self._timeout = settings.timeout_seconds
        self._headers = dict(settings.custom_headers)
        if settings.custom_auth_mode == "bearer":
            self._headers["Authorization"] = f"Bearer {settings.custom_secret}"
        elif settings.custom_auth_mode == "header":
            self._headers[settings.custom_auth_header] = settings.custom_secret
        self._direct_content_type = settings.custom_direct_content_type

    def send(self, event: dict) -> None:
        _post_json(
            self._url,
            event,
            headers=self._headers,
            timeout=self._timeout,
        )

    def test(self) -> None:
        _post_json(
            self._url,
            {
                "event": "passkey_auth.telemetry_test",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "passkey-auth",
                "test": True,
            },
            headers=self._headers,
            timeout=self._timeout,
        )

    def create_direct_target(self, metadata: dict) -> dict:
        return {
            "url": self._url,
            "headers": self._headers,
            "contentType": self._direct_content_type,
            "opaque": (
                self._direct_content_type == "text/plain"
                and not self._headers
            ),
        }


def _post_json(
    url: str,
    payload: dict,
    *,
    headers: dict[str, str],
    timeout: float,
) -> None:
    request_headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        **headers,
    }
    request = Request(
        url,
        data=json.dumps(
            payload,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8"),
        headers=request_headers,
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            response.read(4096)
    except HTTPError as error:
        raise RuntimeError(f"telemetry_http_{error.code}") from None
    except (URLError, TimeoutError, OSError):
        raise RuntimeError("telemetry_unavailable") from None
