from __future__ import annotations

import importlib.util
import json
import os
import re
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import urlsplit
from unittest.mock import patch

from jstu_passkey.app import create_app


class TelemetryBackendTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.previous_env = {
            key: os.environ.get(key)
            for key in (
                "PASSKEY_DATABASE",
                "PASSKEY_TELEMETRY_DATABASE",
                "PASSKEY_TELEMETRY_TOKEN_URL",
                "PASSKEY_TELEMETRY_API_KEY",
                "FLASK_SECRET_KEY",
            )
        }
        os.environ["PASSKEY_DATABASE"] = os.path.join(
            self.tempdir.name,
            "passkeys.sqlite3",
        )
        os.environ["PASSKEY_TELEMETRY_DATABASE"] = os.path.join(
            self.tempdir.name,
            "telemetry.sqlite3",
        )
        os.environ["FLASK_SECRET_KEY"] = "telemetry-backend-test-secret"
        os.environ.pop("PASSKEY_TELEMETRY_TOKEN_URL", None)
        os.environ.pop("PASSKEY_TELEMETRY_API_KEY", None)
        self.app = create_app()
        self.app.testing = True
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        for key, value in self.previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.tempdir.cleanup()

    def test_builtin_is_default_and_external_modules_stay_unloaded(self) -> None:
        runtime = self.app.extensions["telemetry_runtime"]

        settings = runtime.settings_payload()

        self.assertEqual(settings["backend"], "builtin")
        self.assertEqual(settings["deliveryMode"], "relay")
        self.assertEqual(settings["delivery"]["state"], "builtin")
        self.assertNotIn(
            "jstu_passkey.telemetry_backends.jason_telemetry_integrate",
            __import__("sys").modules,
        )

    def test_custom_direct_target_bypasses_local_collector_and_database(self) -> None:
        runtime = self.app.extensions["telemetry_runtime"]
        runtime.update_settings(
            enabled=True,
            anonymous_enabled=True,
            default_features=["screen"],
            retention_days=30,
            backend="custom",
            delivery_mode="direct",
            custom_url="https://collector.example/events",
            custom_auth_mode="none",
            custom_headers={"X-Source": "passkey-auth"},
            custom_direct_content_type="application/json",
        )

        page_response = self.client.get("/")
        page = page_response.get_data(as_text=True)
        token = re.search(
            r'data-passkey-telemetry-token="([^"]+)"',
            page,
        ).group(1)
        response = self.client.post(
            "/api/telemetry/direct-target",
            json={"token": token},
        )

        self.assertEqual(response.status_code, 200)
        target = response.get_json()["target"]
        self.assertEqual(target["url"], "https://collector.example/events")
        self.assertEqual(target["headers"], {"X-Source": "passkey-auth"})
        self.assertIn('data-passkey-telemetry-delivery="direct"', page)
        self.assertIn(
            'data-passkey-telemetry-endpoint="/api/telemetry/direct-target"',
            page,
        )
        self.assertIn(
            "connect-src 'self' https://collector.example",
            page_response.headers["Content-Security-Policy"],
        )
        self.assertFalse(
            os.path.exists(os.environ["PASSKEY_TELEMETRY_DATABASE"])
        )

    def test_custom_direct_rejects_private_authentication(self) -> None:
        runtime = self.app.extensions["telemetry_runtime"]

        with self.assertRaisesRegex(ValueError, "浏览器直连"):
            runtime.update_settings(
                enabled=True,
                anonymous_enabled=True,
                default_features=["screen"],
                retention_days=30,
                backend="custom",
                delivery_mode="direct",
                custom_url="https://collector.example/events",
                custom_auth_mode="bearer",
                custom_secret="private-secret",
            )

    def test_jason_v13_pairing_relay_and_direct_paths(self) -> None:
        pairing_code = "passkey-pairing-code-2026"
        v13_data = Path(self.tempdir.name) / "jason-v13"
        previous = {
            key: os.environ.get(key)
            for key in (
                "TELEMETRY_DATA_DIR",
                "TELEMETRY_PASSKEY_PAIRING_CODE",
                "TELEMETRY_API_KEY",
            )
        }
        os.environ["TELEMETRY_DATA_DIR"] = str(v13_data)
        os.environ["TELEMETRY_PASSKEY_PAIRING_CODE"] = pairing_code
        os.environ["TELEMETRY_API_KEY"] = "af00-af00-af00-af00"
        try:
            source = (
                Path(__file__).resolve().parents[1]
                / "integrations"
                / "jason-telemetry"
                / "telemetry_server_v13_both.py"
            )
            spec = importlib.util.spec_from_file_location(
                f"jason_telemetry_v13_test_{time.time_ns()}",
                source,
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            module.init_csv()
            module.init_api_log()
            module.init_statistics()
            module.init_api_keys()
            module.init_email_links()
            module.init_passkey_pairing()
            v13_client = module.app.test_client()
            base_url = "http://127.0.0.1:15000"

            def bridge(url, *, method, payload, timeout):
                del timeout
                response = v13_client.open(
                    urlsplit(url).path,
                    method=method,
                    json=payload,
                    environ_base={"REMOTE_ADDR": "127.0.0.1"},
                )
                if response.status_code >= 400:
                    raise RuntimeError(f"telemetry_http_{response.status_code}")
                value = response.get_json(silent=True)
                return value if isinstance(value, dict) else {}

            with patch(
                "jstu_passkey.telemetry_backends."
                "jason_telemetry_integrate._json_request",
                side_effect=bridge,
            ):
                runtime = self.app.extensions["telemetry_runtime"]
                paired = runtime.pair_jason(
                    base_url=base_url,
                    pairing_code=pairing_code,
                    timeout_seconds=1,
                )

                self.assertTrue(paired["apiKeyConfigured"])
                self.assertEqual(paired["serverVersion"], "13.0.0")
                settings = runtime.settings_payload()
                self.assertTrue(settings["jason"]["apiKeyConfigured"])
                self.assertNotIn("apiKey", settings["jason"])
                self.assertTrue(runtime.test_backend()["ok"])
                saved_keys = json.loads(
                    (v13_data / "api_keys.json").read_text(encoding="utf-8")
                )
                paired_keys = [
                    key
                    for key, value in saved_keys.items()
                    if value.get("created_by") == "passkey-auth-v13-pairing"
                ]
                self.assertEqual(len(paired_keys), 1)
                pairing_state = (
                    v13_data / "passkey_pairing_state.json"
                ).read_text(encoding="utf-8")
                self.assertNotIn(pairing_code, pairing_state)
                self.assertIn("consumed_code_hashes", pairing_state)
                reused = v13_client.post(
                    "/v13/integrations/passkey-auth/pairing/challenge",
                    json={},
                    environ_base={"REMOTE_ADDR": "127.0.0.1"},
                )
                self.assertEqual(reused.status_code, 410)

                runtime.update_settings(
                    enabled=True,
                    anonymous_enabled=True,
                    default_features=["screen"],
                    retention_days=30,
                    backend="jason",
                    delivery_mode="relay",
                )
                self._submit_screen_sample(runtime)
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    rows = (v13_data / "telemetry.csv").read_text(
                        encoding="utf-8"
                    ).splitlines()
                    if len(rows) > 1:
                        break
                    time.sleep(0.05)
                self.assertGreater(len(rows), 1)
                self.assertFalse(
                    os.path.exists(os.environ["PASSKEY_TELEMETRY_DATABASE"])
                )

                runtime.update_settings(
                    enabled=True,
                    anonymous_enabled=True,
                    default_features=["screen"],
                    retention_days=30,
                    backend="jason",
                    delivery_mode="direct",
                )
                page = self.client.get("/").get_data(as_text=True)
                token = re.search(
                    r'data-passkey-telemetry-token="([^"]+)"',
                    page,
                ).group(1)
                target = self.client.post(
                    "/api/telemetry/direct-target",
                    json={"token": token},
                ).get_json()["target"]
                response = v13_client.post(
                    urlsplit(target["url"]).path,
                    data=json.dumps(
                        {
                            "event": "passkey_auth.browser_telemetry",
                            "screen": {},
                        }
                    ),
                    content_type="text/plain;charset=UTF-8",
                    environ_base={"REMOTE_ADDR": "127.0.0.1"},
                )
                self.assertEqual(response.status_code, 200)
                self.assertTrue((v13_data / "device_info.jsonl").exists())
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def _submit_screen_sample(self, runtime) -> None:
        page = self.client.get("/").get_data(as_text=True)
        token = re.search(
            r'data-passkey-telemetry-token="([^"]+)"',
            page,
        ).group(1)
        response = self.client.post(
            "/api/telemetry/collect",
            json={
                "token": token,
                "features": ["screen"],
                "path": "/",
                "referrerOrigin": "",
                "client": {"osFamily": "macos", "deviceClass": "desktop"},
                "signals": {
                    "screen": {
                        "width": 1512,
                        "height": 982,
                        "pixelRatio": 2,
                    }
                },
            },
            headers={"User-Agent": "Mozilla/5.0 Safari/605.1.15"},
        )
        self.assertEqual(response.status_code, 202)
        self.assertTrue(response.get_json()["queued"])


if __name__ == "__main__":
    unittest.main()
