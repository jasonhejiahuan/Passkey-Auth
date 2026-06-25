import json
import os
import re
import tempfile
import unittest
from unittest import mock

from jstu_passkey.app import create_app


class TelemetryIntegrationTest(unittest.TestCase):
    def setUp(self):
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
        os.environ["FLASK_SECRET_KEY"] = "telemetry-integration-secret"
        os.environ.pop("PASSKEY_TELEMETRY_TOKEN_URL", None)
        os.environ.pop("PASSKEY_TELEMETRY_API_KEY", None)
        self.app = create_app()
        self.app.testing = True
        self.client = self.app.test_client()

    def tearDown(self):
        for key, value in self.previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.tempdir.cleanup()

    def test_global_off_skips_injection_and_never_opens_telemetry_database(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"/static/telemetry.js", response.data)
        self.assertFalse(
            os.path.exists(os.environ["PASSKEY_TELEMETRY_DATABASE"])
        )

    def test_anonymous_policy_injects_signed_local_collector(self):
        runtime = self.app.extensions["telemetry_runtime"]
        runtime.update_settings(
            enabled=True,
            anonymous_enabled=True,
            default_features=["screen", "hardware"],
            retention_days=30,
        )

        response = self.client.get("/")
        body = response.get_data(as_text=True)

        self.assertIn("/static/telemetry.js", body)
        self.assertIn('data-passkey-telemetry-endpoint="/api/telemetry/collect"', body)
        self.assertIn('data-passkey-telemetry-features="screen,hardware"', body)
        self.assertNotIn("telemetry-integration-secret", body)

    def test_per_user_off_omits_the_script_and_custom_policy_trims_features(self):
        store = self.app.extensions["passkey_store"]
        user = store.create_user("telemetry-user", b"u" * 32)
        runtime = self.app.extensions["telemetry_runtime"]
        runtime.update_settings(
            enabled=True,
            anonymous_enabled=False,
            default_features=["screen", "hardware", "preferences"],
            retention_days=30,
        )
        runtime.update_user_policy(user_id=user.id, mode="off", features=[])
        with self.client.session_transaction() as session:
            session["signed_in_user_id"] = user.id
            session["signed_in_session_version"] = user.session_version

        self.assertNotIn(b"/static/telemetry.js", self.client.get("/").data)

        runtime.update_user_policy(
            user_id=user.id,
            mode="custom",
            features=["screen", "fonts"],
        )
        body = self.client.get("/").get_data(as_text=True)
        self.assertIn('data-passkey-telemetry-features="screen,fonts"', body)
        self.assertNotIn("hardware,preferences", body)

    def test_collection_is_one_time_and_statistics_are_available(self):
        runtime = self.app.extensions["telemetry_runtime"]
        runtime.update_settings(
            enabled=True,
            anonymous_enabled=True,
            default_features=["screen", "hardware", "preferences"],
            retention_days=30,
        )
        body = self.client.get("/").get_data(as_text=True)
        token = re.search(
            r'data-passkey-telemetry-token="([^"]+)"',
            body,
        ).group(1)
        payload = {
            "token": token,
            "features": ["screen", "hardware", "preferences"],
            "path": "/",
            "referrerOrigin": "",
            "client": {"osFamily": "macos", "deviceClass": "desktop"},
            "signals": {
                "screen": {
                    "width": 1512,
                    "height": 982,
                    "pixelRatio": 2,
                    "colorDepth": 30,
                },
                "hardware": {
                    "logicalProcessors": 10,
                    "deviceMemoryGb": 0,
                    "architecture": "arm",
                },
                "preferences": {
                    "colorScheme": "dark",
                    "reducedMotion": False,
                    "contrast": "default",
                    "forcedColors": False,
                },
            },
        }

        first = self.client.post(
            "/api/telemetry/collect",
            json=payload,
            headers={"User-Agent": "Mozilla/5.0 Version/26.0 Safari/605.1.15"},
        )
        second = self.client.post(
            "/api/telemetry/collect",
            json=payload,
            headers={"User-Agent": "Mozilla/5.0 Version/26.0 Safari/605.1.15"},
        )

        self.assertEqual(first.status_code, 202)
        self.assertFalse(first.get_json()["duplicate"])
        self.assertEqual(second.status_code, 202)
        self.assertTrue(second.get_json()["duplicate"])
        stats = runtime.statistics()
        self.assertEqual(stats["summary"]["total"], 1)
        self.assertEqual(
            stats["distributions"]["operatingSystems"],
            [{"label": "macos", "count": 1}],
        )
        self.assertEqual(stats["recent"][0]["browserFamily"], "safari")
        self.assertNotIn("ip_address", stats["recent"][0])

    def test_browser_modules_are_os_specific_and_no_iframe_is_created(self):
        response = self.client.get("/static/telemetry.js")
        body = response.get_data(as_text=True)

        self.assertIn('windows: "/static/telemetry/fonts-windows.js"', body)
        self.assertIn('macos: "/static/telemetry/fonts-macos.js"', body)
        self.assertIn("requestIdleCallback", body)
        self.assertIn("sendBeacon", body)
        self.assertNotIn("createElement(\"iframe\")", body)
        self.assertNotIn("Segoe UI", body)

    def test_legacy_browser_token_endpoint_keeps_api_key_server_side(self):
        os.environ["PASSKEY_TELEMETRY_TOKEN_URL"] = (
            "http://telemetry.local/v12/key/browser-token"
        )
        os.environ["PASSKEY_TELEMETRY_API_KEY"] = "abcd-abcd-abcd-abcd"
        app = create_app()
        client = app.test_client()
        telemetry_response = _TelemetryResponse(
            {"status": "created", "status_path": "/v12/browser/token/status"}
        )

        with mock.patch("jstu_passkey.app.urlopen", return_value=telemetry_response) as urlopen:
            response = client.post(
                "/api/telemetry/browser-token",
                json={"path": "/", "referrer": ""},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {"ok": True, "statusUrl": "/v12/browser/token/status"},
        )
        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_header("X-api-key"), "abcd-abcd-abcd-abcd")
        self.assertNotIn("abcd-abcd-abcd-abcd", response.get_data(as_text=True))


class _TelemetryResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self):
        return self.payload


if __name__ == "__main__":
    unittest.main()
