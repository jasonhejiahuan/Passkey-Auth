from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest

from jstu_passkey.storage import PasskeyStore


class OAuthCodeStorageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.database_path = os.path.join(self.tempdir.name, "passkeys.sqlite3")
        self.store = PasskeyStore(self.database_path)
        self.user = self.store.create_user("jason", b"stable-user-handle")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_authorization_code_uses_kdf_digest_and_is_consumed_once(self) -> None:
        code = self.store.create_oauth_authorization_code(
            client_id="jstu-passkey-client",
            redirect_uri="https://login.example/callback",
            user_id=self.user.id,
            ttl_seconds=300,
            code_factory=lambda: "test-code",
        )

        with sqlite3.connect(self.database_path) as conn:
            row = conn.execute(
                "SELECT code_hash FROM oauth_authorization_codes"
            ).fetchone()

        stored_digest = row[0]
        legacy_sha256_digest = (
            "3a5f4b089cfd9588a00d4da744493979993cd87e5361d2720acc36a83eb8c04d"
        )
        self.assertTrue(stored_digest.startswith("pbkdf2_sha256$120000$"))
        self.assertNotEqual(stored_digest, legacy_sha256_digest)
        self.assertNotIn(code, stored_digest)

        consumed = self.store.consume_oauth_authorization_code(
            code=code,
            client_id="jstu-passkey-client",
            redirect_uri="https://login.example/callback",
        )
        self.assertIsNotNone(consumed)

        replay = self.store.consume_oauth_authorization_code(
            code=code,
            client_id="jstu-passkey-client",
            redirect_uri="https://login.example/callback",
        )
        self.assertIsNone(replay)


if __name__ == "__main__":
    unittest.main()
