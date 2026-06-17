import os
import unittest

from passkey_demo.app import create_app


class ErrorPageTest(unittest.TestCase):
    def setUp(self):
        os.environ["PASSKEY_DATABASE"] = ":memory:"
        self.app = create_app()
        self.client = self.app.test_client()

    def tearDown(self):
        os.environ.pop("PASSKEY_DATABASE", None)

    def test_edge_error_page_uses_status_label(self):
        response = self.client.get("/_error/404")

        self.assertEqual(response.status_code, 404)
        self.assertIn(b"404", response.data)
        self.assertIn(b"Not Found", response.data)
        self.assertIn(b"<title>404", response.data)
        self.assertNotIn(b"Jason Studio", response.data)

    def test_edge_error_page_supports_server_errors(self):
        response = self.client.get("/_error/500")

        self.assertEqual(response.status_code, 500)
        self.assertIn(b"500", response.data)
        self.assertIn(b"Internal Server Error", response.data)

    def test_edge_error_page_marks_unlisted_errors_as_unknown_ungix(self):
        response = self.client.get("/_error/418")

        self.assertEqual(response.status_code, 418)
        self.assertIn(b"418", response.data)
        self.assertIn(b"Unknown Ungix Error", response.data)

    def test_edge_error_page_falls_back_when_status_is_invalid(self):
        response = self.client.get("/_error/999")

        self.assertEqual(response.status_code, 404)
        self.assertIn(b"404", response.data)
        self.assertIn(b"Unknown Ungix Error", response.data)

    def test_unknown_route_uses_error_page(self):
        response = self.client.get("/missing-page")

        self.assertEqual(response.status_code, 404)
        self.assertIn(b"404", response.data)
        self.assertIn(b"Not Found", response.data)


if __name__ == "__main__":
    unittest.main()
