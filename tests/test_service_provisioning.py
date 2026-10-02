from base64 import urlsafe_b64encode
import os
from pathlib import Path
import tempfile
import unittest

from scripts.grant_admin import grant
from scripts.provision_service import provision
from jstu_passkey.storage import PasskeyStore


class ServiceProvisioningTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.options = dict(database=self.root / 'auth.sqlite3', environment=self.root / 'service.env',
                            client_secret_file=self.root / 'ppq-secret', origin='https://auth.example',
                            redirect_uri='https://ppq.example/api/auth/callback')

    def tearDown(self):
        self.directory.cleanup()

    def test_provisions_exact_client_and_private_files_without_creating_user(self):
        metadata = provision(**self.options, enable_registration=True)
        store = PasskeyStore(self.options['database'])
        client = store.get_oauth_client('ppq-practice')
        self.assertFalse(client.is_demo)
        self.assertEqual(client.redirect_uris, [self.options['redirect_uri']])
        secret = self.options['client_secret_file'].read_text().strip()
        self.assertTrue(store.verify_oauth_client_secret('ppq-practice', secret))
        self.assertNotIn(secret, str(metadata))
        self.assertTrue(store.get_registration_settings().mode == 'open')
        self.assertIsNone(store.get_user_by_username('Jason'))
        for key in ['database', 'environment', 'client_secret_file']:
            self.assertEqual(self.options[key].stat().st_mode & 0o077, 0)

    def test_rerun_preserves_signing_and_client_secrets(self):
        provision(**self.options)
        before = {key: self.options[key].read_bytes() for key in ['environment', 'client_secret_file']}
        provision(**self.options)
        self.assertEqual(before, {key: self.options[key].read_bytes() for key in before})
        self.assertEqual(PasskeyStore(self.options['database']).get_registration_settings().mode, 'closed')

    def test_rejects_cross_origin_reuse_and_public_secret_permissions(self):
        provision(**self.options)
        with self.assertRaises(ValueError):
            provision(**{**self.options, 'origin': 'https://different.example'})
        os.chmod(self.options['client_secret_file'], 0o644)
        with self.assertRaises(ValueError):
            provision(**self.options)

    def test_operator_promotes_only_exact_existing_subject(self):
        provision(**self.options)
        store = PasskeyStore(self.options['database'])
        user = store.create_user('Jason', b'stable-user-handle')
        store.set_permissions(user.id, {'admin': False, 'login': True, 'demo': False})
        with self.assertRaises(ValueError):
            grant(self.options['database'], urlsafe_b64encode(b'unknown-handle').decode().rstrip('='))
        self.assertFalse(store.get_permissions(user.id)['admin'])
        grant(self.options['database'], urlsafe_b64encode(user.user_handle).decode().rstrip('='))
        self.assertEqual(store.get_permissions(user.id), {'admin': True, 'login': True, 'demo': False})


if __name__ == '__main__':
    unittest.main()
