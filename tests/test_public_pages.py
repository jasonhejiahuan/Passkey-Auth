import os
import unittest
from urllib.parse import urlencode

from passkey_demo.app import create_app


class PublicPageTest(unittest.TestCase):
    def setUp(self):
        os.environ["PASSKEY_DATABASE"] = ":memory:"
        self.app = create_app()
        self.client = self.app.test_client()

    def tearDown(self):
        os.environ.pop("PASSKEY_DATABASE", None)
        os.environ.pop("PASSKEY_TELEMETRY_TOKEN_URL", None)
        os.environ.pop("PASSKEY_TELEMETRY_API_KEY", None)

    def test_index_is_static_jason_studio_logo_page(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"<title>Jason Studio</title>", response.data)
        self.assertIn(b"jason-logo-black.png", response.data)
        self.assertNotIn(b"main.js", response.data)
        self.assertNotIn(b"telemetry.js", response.data)
        self.assertNotIn(b"id=\"logo-button\"", response.data)

    def test_oauth_authorize_uses_jason_passkey_title(self):
        query = urlencode(
            {
                "response_type": "code",
                "client_id": "passkey-demo-client",
                "redirect_uri": "http://localhost/demo/oauth/callback",
                "state": "state-value",
            }
        )

        response = self.client.get(f"/oauth/authorize?{query}")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"<title>Jason Passkey</title>", response.data)
        self.assertIn(b"oauth_authorize.js", response.data)

    def test_global_logo_size_stays_small(self):
        response = self.client.get("/static/styles.css")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"width: 30vw", response.data)
        self.assertIn(b"max-width: 220px", response.data)
        self.assertIn(b"width: 46vw", response.data)
        self.assertIn(b"max-width: 180px", response.data)
        self.assertNotIn(b"width: min(38vw, 300px)", response.data)
        self.assertNotIn(b"width: min(54vw, 240px)", response.data)

    def test_browser_telemetry_script_is_injected_when_configured(self):
        os.environ["PASSKEY_TELEMETRY_TOKEN_URL"] = "http://127.0.0.1:15000/v12/key/browser-token"
        os.environ["PASSKEY_TELEMETRY_API_KEY"] = "abcd-abcd-abcd-abcd"
        app = create_app()
        client = app.test_client()

        response = client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"/static/telemetry.js", response.data)
        self.assertIn(b"data-passkey-telemetry-token-url", response.data)
        self.assertNotIn(b"abcd-abcd-abcd-abcd", response.data)


if __name__ == "__main__":
    unittest.main()
