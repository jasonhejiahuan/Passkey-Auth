from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from unittest.mock import patch

from jstu_passkey.desktop import _open_browser_when_ready, configure_desktop_environment


class DesktopLauncherTest(unittest.TestCase):
    def setUp(self) -> None:
        self.keys = (
            "PASSKEY_DATABASE",
            "FLASK_SECRET_KEY",
            "PASSKEY_ORIGIN",
            "HOST",
            "PORT",
        )
        self.previous = {key: os.environ.get(key) for key in self.keys}
        for key in self.keys:
            os.environ.pop(key, None)
        self.tempdir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        for key, value in self.previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.tempdir.cleanup()

    def test_desktop_environment_uses_persistent_user_data(self) -> None:
        data_dir = Path(self.tempdir.name)

        configure_desktop_environment(data_dir)
        first_secret = os.environ["FLASK_SECRET_KEY"]
        os.environ.pop("FLASK_SECRET_KEY")
        configure_desktop_environment(data_dir)

        self.assertEqual(
            os.environ["PASSKEY_DATABASE"],
            str(data_dir / "passkeys-v2.sqlite3"),
        )
        self.assertEqual(os.environ["FLASK_SECRET_KEY"], first_secret)
        self.assertEqual(os.environ["PASSKEY_ORIGIN"], "http://localhost:5003")
        self.assertTrue((data_dir / "flask-secret").exists())

    @patch("jstu_passkey.desktop.webbrowser.open")
    @patch("jstu_passkey.desktop.socket.create_connection")
    def test_loopback_server_opens_localhost_origin(
        self,
        create_connection,
        open_browser,
    ) -> None:
        create_connection.return_value.__enter__.return_value = object()

        _open_browser_when_ready("127.0.0.1", 5003)

        open_browser.assert_called_once_with("http://localhost:5003/")


if __name__ == "__main__":
    unittest.main()
