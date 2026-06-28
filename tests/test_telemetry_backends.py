from __future__ import annotations

import os
import re
import tempfile
import unittest

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

if __name__ == "__main__":
    unittest.main()
