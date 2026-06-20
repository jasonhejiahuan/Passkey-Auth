from __future__ import annotations

import os
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from unittest import mock

from jstu_passkey.app import (
    _validate_admin_recovery_token,
    create_app,
    main,
)
from jstu_passkey.storage import PasskeyStore


class AdminRecoveryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.database_path = os.path.join(self.tempdir.name, "recovery.sqlite3")
        self.previous_env = {
            key: os.environ.get(key)
            for key in (
                "PASSKEY_DATABASE",
                "FLASK_SECRET_KEY",
                "PASSKEY_TELEMETRY_TOKEN_URL",
                "PASSKEY_TELEMETRY_API_KEY",
            )
        }
        os.environ["PASSKEY_DATABASE"] = self.database_path
        os.environ["FLASK_SECRET_KEY"] = "recovery-test-secret"
        self.app = create_app()
        self.app.testing = True
        self.client = self.app.test_client()
        self.store = PasskeyStore(self.database_path)

    def tearDown(self) -> None:
        for key, value in self.previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.tempdir.cleanup()

    def test_token_format_and_route_conflicts_fail(self) -> None:
        self.assertIsNotNone(_validate_admin_recovery_token(self.app, "short"))
        self.assertIsNotNone(_validate_admin_recovery_token(self.app, "management"))
        self.assertIsNotNone(_validate_admin_recovery_token(self.app, "MANAGEMENT"))
        self.assertIsNone(_validate_admin_recovery_token(self.app, "qpwoeiruty"))

    def test_invalid_cli_token_prints_banner_and_does_not_start_server(self) -> None:
        output = StringIO()
        with mock.patch("jstu_passkey.app.app.run") as run, redirect_stderr(output):
            status = main(["--reregister-admin", "management"])
        self.assertEqual(status, 2)
        run.assert_not_called()
        message = output.getvalue()
        self.assertIn("PASSKEY-AUTH STARTUP ERROR", message)
        self.assertIn("Server was not started", message)
        self.assertNotIn("Token: management", message)

    def test_recovery_page_only_exists_for_unused_token(self) -> None:
        self.assertTrue(self.store.add_admin_recovery_token("qpwoeiruty"))
        response = self.client.get("/qpwoeiruty")
        self.assertEqual(response.status_code, 200)
        self.assertIn("管理员用户名", response.get_data(as_text=True))
        self.assertTrue(self.store.consume_admin_recovery_token("qpwoeiruty"))
        response = self.client.get("/qpwoeiruty")
        self.assertEqual(response.status_code, 404)

    def test_recovery_page_never_injects_telemetry(self) -> None:
        os.environ["PASSKEY_TELEMETRY_TOKEN_URL"] = (
            "http://127.0.0.1:15000/v12/key/browser-token"
        )
        os.environ["PASSKEY_TELEMETRY_API_KEY"] = "server-only-key"
        app = create_app()
        app.testing = True
        store = app.extensions["passkey_store"]
        self.assertTrue(store.add_admin_recovery_token("telemetry123"))

        response = app.test_client().get("/telemetry123")

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("telemetry.js", response.get_data(as_text=True))

    def test_duplicate_username_is_rejected_before_webauthn_options(self) -> None:
        self.assertTrue(self.store.add_admin_recovery_token("qpwoeiruty"))
        self.store.create_user("af00", b"a" * 32)
        response = self.client.post(
            "/qpwoeiruty/options",
            json={"username": "af00"},
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()["error"], "用户名已注册")

    def test_complete_recovery_is_single_use_and_grants_full_permissions(self) -> None:
        self.assertTrue(self.store.add_admin_recovery_token("qpwoeiruty"))
        self.assertTrue(
            self.store.reserve_username(
                username="operator",
                reservation_token="reservation",
                ttl_seconds=300,
            )
        )
        user = self.store.complete_admin_recovery(
            token="qpwoeiruty",
            username="operator",
            user_handle=b"u" * 32,
            reservation_token="reservation",
            credential_id=b"credential",
            public_key=b"public-key",
            sign_count=0,
            transports=["internal"],
            aaguid=None,
            credential_type="public-key",
            device_type="single_device",
            backed_up=False,
        )
        self.assertIsNotNone(user)
        self.assertEqual(
            self.store.get_permissions(user.id),
            {"admin": True, "login": True, "demo": True},
        )
        self.assertFalse(self.store.admin_recovery_available("qpwoeiruty"))


if __name__ == "__main__":
    unittest.main()
