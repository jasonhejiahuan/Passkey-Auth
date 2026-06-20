import json
import os
import unittest
from unittest import mock

from jstu_passkey.app import create_app


class TelemetryIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.previous_env = {
            "PASSKEY_DATABASE": os.environ.get("PASSKEY_DATABASE"),
            "PASSKEY_TELEMETRY_TOKEN_URL": os.environ.get("PASSKEY_TELEMETRY_TOKEN_URL"),
            "PASSKEY_TELEMETRY_API_KEY": os.environ.get("PASSKEY_TELEMETRY_API_KEY"),
        }
        os.environ["PASSKEY_DATABASE"] = ":memory:"
        os.environ["PASSKEY_TELEMETRY_TOKEN_URL"] = "http://telemetry.local/v12/key/browser-token"
        os.environ["PASSKEY_TELEMETRY_API_KEY"] = "abcd-abcd-abcd-abcd"
        self.app = create_app()
        self.client = self.app.test_client()

    def tearDown(self):
        for key, value in self.previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_browser_token_endpoint_keeps_api_key_server_side(self):
        telemetry_response = _TelemetryResponse(
            {"status": "created", "status_path": "/v12/browser/token/status"}
        )

        with mock.patch("jstu_passkey.app.urlopen", return_value=telemetry_response) as urlopen:
            response = self.client.post(
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
