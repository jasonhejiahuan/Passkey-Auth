from __future__ import annotations

import os
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit

from passkey_demo.app import create_app
from passkey_demo.storage import PasskeyStore


class LinkLoginChallengeDemoTest(unittest.TestCase):
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
        self.store = PasskeyStore(self.database_path)
        self.return_uri = "http://localhost/demo/link-login/callback"

    def tearDown(self) -> None:
        for key, value in self.previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.tempdir.cleanup()

    def test_link_login_page_includes_challenge_shape(self) -> None:
        response = self.client.get("/demo/link-login")

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("login.xxxxx demo", body)
        self.assertIn("/oauth/challenge/", body)
        self.assertIn("http://localhost/demo/link-login/callback", body)

    def test_link_login_start_redirects_to_auth_challenge(self) -> None:
        response = self.client.post(
            "/demo/link-login/start",
            data={"username": "jason"},
        )

        self.assertEqual(response.status_code, 302)
        location = response.headers["Location"]
        self.assertIn("/oauth/challenge/", location)
        challenge_id = location.rsplit("/", 1)[-1]
        challenge = self.store.get_oauth_challenge_request(challenge_id)
        self.assertIsNotNone(challenge)
        self.assertEqual(challenge.username, "jason")
        self.assertEqual(challenge.return_uri, self.return_uri)

    def test_auth_challenge_page_binds_username(self) -> None:
        challenge_id = self.store.create_oauth_challenge_request(
            client_id="passkey-demo-client",
            return_uri=self.return_uri,
            username="jason",
            state="state-123",
            ttl_seconds=300,
            challenge_factory=lambda: "challenge-123",
        )

        response = self.client.get(f"/oauth/challenge/{challenge_id}")

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn('data-oauth-mode="challenge"', body)
        self.assertIn('data-challenge-id="challenge-123"', body)
        self.assertIn('data-username="jason"', body)

    def test_challenge_complete_and_callback_succeed_once(self) -> None:
        user = self.store.create_user("jason", b"stable-user-handle")
        challenge_id = self.store.create_oauth_challenge_request(
            client_id="passkey-demo-client",
            return_uri=self.return_uri,
            username="jason",
            state="state-123",
            ttl_seconds=300,
            challenge_factory=lambda: "challenge-123",
        )
        with self.client.session_transaction() as session:
            session["signed_in_user_id"] = user.id
            session["signed_in_session_version"] = user.session_version
            session["link_login_state"] = "state-123"

        response = self.client.post(f"/oauth/challenge/{challenge_id}/complete")

        self.assertEqual(response.status_code, 200)
        redirect_url = response.get_json()["redirectUrl"]
        params = {
            key: values[0]
            for key, values in parse_qs(urlsplit(redirect_url).query).items()
        }
        self.assertEqual(params["challenge"], "challenge-123")
        self.assertEqual(params["state"], "state-123")
        self.assertEqual(params["status"], "success")

        callback = self.client.get(
            "/demo/link-login/callback",
            query_string=params,
        )

        self.assertEqual(callback.status_code, 200)
        body = callback.get_data(as_text=True)
        self.assertIn("原网站登录成功", body)
        self.assertIn("jason", body)

        replay = self.client.get(
            "/demo/link-login/callback",
            query_string=params,
        )
        self.assertIn("invalid_state", replay.get_data(as_text=True))

    def test_challenge_complete_rejects_wrong_signed_in_user(self) -> None:
        user = self.store.create_user("alice", b"stable-user-handle")
        challenge_id = self.store.create_oauth_challenge_request(
            client_id="passkey-demo-client",
            return_uri=self.return_uri,
            username="jason",
            state="state-123",
            ttl_seconds=300,
            challenge_factory=lambda: "challenge-123",
        )
        with self.client.session_transaction() as session:
            session["signed_in_user_id"] = user.id
            session["signed_in_session_version"] = user.session_version

        response = self.client.post(f"/oauth/challenge/{challenge_id}/complete")

        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.get_json()["error"],
            "Passkey 用户和原网站用户名不匹配",
        )


if __name__ == "__main__":
    unittest.main()
