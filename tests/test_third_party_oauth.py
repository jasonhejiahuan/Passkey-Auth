from __future__ import annotations

import os
import tempfile
import unittest

from passkey_demo.app import create_app
from passkey_demo.storage import PasskeyStore


class ThirdPartyOAuthDemoTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.database_path = os.path.join(self.tempdir.name, "passkeys.sqlite3")
        self.previous_env = {
            key: os.environ.get(key)
            for key in (
                "PASSKEY_DATABASE",
                "FLASK_SECRET_KEY",
                "PASSKEY_OAUTH_DEMO_CLIENT_ID",
                "PASSKEY_OAUTH_DEMO_CLIENT_SECRET",
                "PASSKEY_OAUTH_DEMO_REDIRECT_URI",
            )
        }
        os.environ["PASSKEY_DATABASE"] = self.database_path
        os.environ["FLASK_SECRET_KEY"] = "test-secret"
        os.environ["PASSKEY_OAUTH_DEMO_CLIENT_ID"] = "passkey-demo-client"
        os.environ["PASSKEY_OAUTH_DEMO_CLIENT_SECRET"] = "passkey-demo-secret"
        os.environ.pop("PASSKEY_OAUTH_DEMO_REDIRECT_URI", None)
        self.app = create_app()
        self.app.testing = True
        self.client = self.app.test_client()
        self.redirect_uri = "http://localhost/demo/third-party/callback"

    def tearDown(self) -> None:
        for key, value in self.previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.tempdir.cleanup()

    def test_third_party_page_includes_authorize_url(self) -> None:
        response = self.client.get("/demo/third-party")

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("/oauth/authorize", body)
        self.assertIn("redirect_uri=http%3A%2F%2Flocalhost%2Fdemo%2Fthird-party%2Fcallback", body)

    def test_authorize_accepts_third_party_callback(self) -> None:
        response = self.client.get(
            "/oauth/authorize",
            query_string={
                "response_type": "code",
                "client_id": "passkey-demo-client",
                "redirect_uri": self.redirect_uri,
                "state": "state-123",
            },
        )

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn('id="oauth-logo-button"', body)
        self.assertIn("/static/oauth_authorize.js", body)
        self.assertNotIn("使用 Passkey 登录", body)

    def test_authorize_rejects_unknown_callback(self) -> None:
        response = self.client.get(
            "/oauth/authorize",
            query_string={
                "response_type": "code",
                "client_id": "passkey-demo-client",
                "redirect_uri": "http://evil.example/callback",
                "state": "state-123",
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("OAuth client 或 redirect_uri 无效", response.get_data(as_text=True))

    def test_callback_rejects_invalid_state(self) -> None:
        with self.client.session_transaction() as session:
            session["third_party_oauth_state"] = "expected-state"

        response = self.client.get(
            "/demo/third-party/callback",
            query_string={"code": "code-123", "state": "wrong-state"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("invalid_state", response.get_data(as_text=True))

    def test_callback_exchanges_code_and_fetches_userinfo(self) -> None:
        store = PasskeyStore(self.database_path)
        user = store.create_user("jason", b"stable-user-handle")
        code = store.create_oauth_authorization_code(
            client_id="passkey-demo-client",
            redirect_uri=self.redirect_uri,
            user_id=user.id,
            ttl_seconds=300,
            code_factory=lambda: "test-code",
        )
        with self.client.session_transaction() as session:
            session["third_party_oauth_state"] = "expected-state"

        response = self.client.get(
            "/demo/third-party/callback",
            query_string={"code": code, "state": "expected-state"},
        )

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("已跳回第三方网页", body)
        self.assertIn("Token Response", body)
        self.assertIn("Userinfo Response", body)
        self.assertIn("jason", body)


if __name__ == "__main__":
    unittest.main()
