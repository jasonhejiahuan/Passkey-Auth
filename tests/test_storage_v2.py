from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest

from passkey_demo.storage import PasskeyStore


class StorageV2Test(unittest.TestCase):
    def test_legacy_database_is_rejected_without_migration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "legacy.sqlite3")
            with sqlite3.connect(path) as conn:
                conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY)")
            with self.assertRaisesRegex(RuntimeError, "new SQLite database"):
                PasskeyStore(path)

    def test_fresh_database_uses_v2_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = PasskeyStore(os.path.join(directory, "fresh.sqlite3"))
            with store.connect() as conn:
                version = conn.execute("PRAGMA user_version").fetchone()[0]
                tables = {
                    row[0]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
            self.assertEqual(version, 2)
            self.assertIn("user_permissions", tables)
            self.assertIn("login_history", tables)
            self.assertIn("admin_recovery_tokens", tables)


if __name__ == "__main__":
    unittest.main()
