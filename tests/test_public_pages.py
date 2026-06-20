import os
import unittest
from urllib.parse import urlencode

from jstu_passkey.app import create_app


class PublicPageTest(unittest.TestCase):
    def setUp(self):
        self.previous_home_auth = os.environ.get("PASSKEY_HOME_AUTH_ENABLED")
        os.environ["PASSKEY_DATABASE"] = ":memory:"
        os.environ["PASSKEY_HOME_AUTH_ENABLED"] = "false"
        self.app = create_app()
        self.client = self.app.test_client()

    def tearDown(self):
        os.environ.pop("PASSKEY_DATABASE", None)
        if self.previous_home_auth is None:
            os.environ.pop("PASSKEY_HOME_AUTH_ENABLED", None)
        else:
            os.environ["PASSKEY_HOME_AUTH_ENABLED"] = self.previous_home_auth
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

    def test_index_enables_passkey_interactions_when_configured(self):
        os.environ["PASSKEY_HOME_AUTH_ENABLED"] = "true"
        app = create_app()
        client = app.test_client()

        response = client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"/static/main.js", response.data)
        self.assertIn(b"id=\"logo-button\"", response.data)
        self.assertIn(b"id=\"status\"", response.data)

    def test_me_returns_signed_in_username_and_logout_clears_session(self):
        store = self.app.extensions["passkey_store"]
        user = store.create_user("af01", b"a" * 32)
        with self.client.session_transaction() as session:
            session["signed_in_user_id"] = user.id
            session["signed_in_session_version"] = user.session_version

        response = self.client.get("/api/me")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {"authenticated": True, "user": {"username": "af01"}},
        )

        logout_response = self.client.post("/api/logout")

        self.assertEqual(logout_response.status_code, 200)
        self.assertEqual(
            self.client.get("/api/me").get_json(),
            {"authenticated": False},
        )

    def test_main_script_only_shows_session_status_on_home(self):
        response = self.client.get("/static/main.js")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn('window.location.pathname === "/"', body)
        self.assertIn("window.location.reload()", body)
        self.assertIn("refreshSession({ refreshNonHome: true })", body)

    def test_oauth_authorize_uses_jason_passkey_title(self):
        query = urlencode(
            {
                "response_type": "code",
                "client_id": "jstu-passkey-client",
                "redirect_uri": "http://localhost/demo/oauth/callback",
                "state": "state-value",
            }
        )

        response = self.client.get(f"/oauth/authorize?{query}")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"<title>Jason Passkey</title>", response.data)
        self.assertIn(b"oauth_authorize.js", response.data)

    def test_standard_passkey_page_rejects_external_return_url(self):
        response = self.client.get(
            "/auth/passkey?return_to=https://evil.example/callback"
        )

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn('data-oauth-mode="login"', body)
        self.assertIn('data-return-to="/"', body)
        self.assertIn("data-auth-flow-token=", body)

    def test_legacy_login_api_is_removed(self):
        self.assertEqual(self.client.post("/api/login/options").status_code, 404)
        self.assertEqual(self.client.post("/api/login/verify").status_code, 404)

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
