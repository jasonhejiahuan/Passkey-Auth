from __future__ import annotations

import os
import tempfile
import unittest

from jstu_passkey.app import create_app
from jstu_passkey.storage import PasskeyStore


class ThirdPartyOAuthDemoTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.database_path = os.path.join(self.tempdir.name, "passkeys.sqlite3")
        self.previous_env = {
            key: os.environ.get(key)
            for key in (
                "PASSKEY_DATABASE",
                "FLASK_SECRET_KEY",
                "PASSKEY_OAUTH_CLIENT_ID",
                "PASSKEY_OAUTH_CLIENT_SECRET",
                "PASSKEY_OAUTH_CLIENT_NAME",
                "PASSKEY_OAUTH_REDIRECT_URIS",
            )
        }
        os.environ["PASSKEY_DATABASE"] = self.database_path
        os.environ["FLASK_SECRET_KEY"] = "test-secret"
        os.environ.pop("PASSKEY_OAUTH_CLIENT_ID", None)
        os.environ.pop("PASSKEY_OAUTH_CLIENT_SECRET", None)
        os.environ.pop("PASSKEY_OAUTH_CLIENT_NAME", None)
        os.environ.pop("PASSKEY_OAUTH_REDIRECT_URIS", None)
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
                "client_id": "jstu-passkey-client",
                "redirect_uri": self.redirect_uri,
                "state": "state-123",
            },
        )

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn('id="oauth-logo-button"', body)
        self.assertIn("/static/oauth_authorize.js", body)
        self.assertNotIn("使用 Passkey 登录", body)

    def test_authorize_accepts_local_hyping_callback_by_default(self) -> None:
        response = self.client.get(
            "/oauth/authorize",
            query_string={
                "response_type": "code",
                "client_id": "jstu-passkey-client",
                "redirect_uri": "http://localhost:8765/api/auth/callback",
                "state": "state-123",
            },
        )

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn('id="oauth-logo-button"', body)
        self.assertIn('data-redirect-uri="http://localhost:8765/api/auth/callback"', body)
        self.assertIn(
            'data-error-redirect-uri="http://localhost:8765/api/auth/error"',
            body,
        )

    def test_authorize_accepts_configured_production_callback(self) -> None:
        os.environ["PASSKEY_OAUTH_CLIENT_ID"] = "production-client"
        os.environ["PASSKEY_OAUTH_CLIENT_SECRET"] = "production-secret"
        os.environ["PASSKEY_OAUTH_CLIENT_NAME"] = "Production Client"
        os.environ["PASSKEY_OAUTH_REDIRECT_URIS"] = "https://app.example/callback"
        app = create_app()
        client = app.test_client()

        response = client.get(
            "/oauth/authorize",
            query_string={
                "response_type": "code",
                "client_id": "production-client",
                "redirect_uri": "https://app.example/callback",
                "state": "state-123",
            },
        )

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn('data-client-id="production-client"', body)
        self.assertIn('data-redirect-uri="https://app.example/callback"', body)
        self.assertIn('data-error-redirect-uri=""', body)

    def test_token_exchange_accepts_configured_production_client(self) -> None:
        os.environ["PASSKEY_OAUTH_CLIENT_ID"] = "production-client"
        os.environ["PASSKEY_OAUTH_CLIENT_SECRET"] = "production-secret"
        os.environ["PASSKEY_OAUTH_REDIRECT_URIS"] = "https://app.example/callback"
        app = create_app()
        client = app.test_client()
        store = PasskeyStore(self.database_path)
        user = store.create_user("jason", b"stable-user-handle")
        code = store.create_oauth_authorization_code(
            client_id="production-client",
            redirect_uri="https://app.example/callback",
            user_id=user.id,
            ttl_seconds=300,
            code_factory=lambda: "production-code",
        )

        response = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": "production-client",
                "client_secret": "production-secret",
                "code": code,
                "redirect_uri": "https://app.example/callback",
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["token_type"], "Bearer")
        self.assertEqual(payload["user"]["username"], "jason")

    def test_platform_policy_blocks_token_exchange(self) -> None:
        store = PasskeyStore(self.database_path)
        user = store.create_user("blocked", b"blocked-user-handle")
        store.set_platform_policy(
            user.id,
            "deny_only",
            ["jstu-passkey-client"],
        )
        code = store.create_oauth_authorization_code(
            client_id="jstu-passkey-client",
            redirect_uri=self.redirect_uri,
            user_id=user.id,
            ttl_seconds=300,
            code_factory=lambda: "blocked-code",
        )

        response = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": "jstu-passkey-client",
                "client_secret": "jstu-passkey-secret",
                "code": code,
                "redirect_uri": self.redirect_uri,
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "invalid_grant")

    def test_demo_permission_blocks_builtin_demo_redirect(self) -> None:
        store = PasskeyStore(self.database_path)
        user = store.create_user("no-demo", b"no-demo-user-handle")
        store.set_permissions(
            user.id,
            {"admin": False, "login": True, "demo": False},
        )
        code = store.create_oauth_authorization_code(
            client_id="jstu-passkey-client",
            redirect_uri=self.redirect_uri,
            user_id=user.id,
            ttl_seconds=300,
            code_factory=lambda: "no-demo-code",
        )

        response = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": "jstu-passkey-client",
                "client_secret": "jstu-passkey-secret",
                "code": code,
                "redirect_uri": self.redirect_uri,
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "invalid_grant")

    def test_session_version_revokes_existing_access_token(self) -> None:
        store = PasskeyStore(self.database_path)
        user = store.create_user("jason", b"stable-token-user")
        code = store.create_oauth_authorization_code(
            client_id="jstu-passkey-client",
            redirect_uri=self.redirect_uri,
            user_id=user.id,
            ttl_seconds=300,
            code_factory=lambda: "revocable-code",
        )
        token_response = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": "jstu-passkey-client",
                "client_secret": "jstu-passkey-secret",
                "code": code,
                "redirect_uri": self.redirect_uri,
            },
        )
        access_token = token_response.get_json()["access_token"]
        store.bump_session_version(user.id)

        response = self.client.get(
            "/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        self.assertEqual(response.status_code, 401)

    def test_demo_page_uses_standard_oauth_client_config(self) -> None:
        os.environ["PASSKEY_OAUTH_CLIENT_ID"] = "production-client"
        os.environ["PASSKEY_OAUTH_CLIENT_SECRET"] = "production-secret"
        app = create_app()
        client = app.test_client()

        response = client.get("/demo/third-party")

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("client_id=production-client", body)
        self.assertNotIn("client_id=jstu-passkey-client", body)

    def test_authorize_rejects_unknown_callback(self) -> None:
        response = self.client.get(
            "/oauth/authorize",
            query_string={
                "response_type": "code",
                "client_id": "jstu-passkey-client",
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
            client_id="jstu-passkey-client",
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
