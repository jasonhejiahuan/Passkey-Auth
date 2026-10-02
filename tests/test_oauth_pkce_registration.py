from __future__ import annotations

import hashlib
import os
import tempfile
import time
import unittest
from base64 import urlsafe_b64encode
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from jstu_passkey.app import create_app
from jstu_passkey.oauth_security import new_authorization_code, verify_code_pkce
from jstu_passkey.webauthn_service import RegistrationResult


class OAuthPKCERegistrationTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {
            'PASSKEY_DATABASE': os.path.join(self.tempdir.name, 'passkey.sqlite3'),
            'FLASK_SECRET_KEY': 'test-oauth-key',
            'PASSKEY_ORIGIN': 'https://auth.example',
            'PASSKEY_REGISTRATION_ENABLED': 'false',
            'PASSKEY_OAUTH_CLIENT_ID': 'ppq-test',
            'PASSKEY_OAUTH_CLIENT_SECRET': 'test-only-secret',
            'PASSKEY_OAUTH_REDIRECT_URIS': 'https://ppq.example/api/auth/callback',
        })
        self.env.start()
        self.app = create_app()
        self.app.testing = True
        self.client = self.app.test_client()
        self.store = self.app.extensions['passkey_store']
        self.verifier = 'a' * 43
        self.challenge = urlsafe_b64encode(hashlib.sha256(self.verifier.encode()).digest()).decode().rstrip('=')
        self.params = {
            'response_type': 'code', 'client_id': 'ppq-test',
            'redirect_uri': 'https://ppq.example/api/auth/callback',
            'state': 'bound-state', 'code_challenge': self.challenge,
            'code_challenge_method': 'S256',
        }

    def tearDown(self):
        self.env.stop()
        self.tempdir.cleanup()

    def authorize(self, **extra):
        return self.client.get('/oauth/authorize', query_string={**self.params, **extra})

    def complete(self, **extra):
        return self.client.post('/oauth/authorize/complete', json={**self.params, **extra})

    def authenticate_for_test(self):
        user = self.store.create_user('alice', b'a' * 32)
        with self.client.session_transaction() as session:
            session['signed_in_user_id'] = user.id
            session['signed_in_session_version'] = user.session_version
            session['oauth_request'] = {**session['oauth_request'], 'authenticated_user_id': user.id}
        return user

    def token(self, code, verifier=None):
        return self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code', 'client_id': 'ppq-test',
            'client_secret': 'test-only-secret', 'redirect_uri': self.params['redirect_uri'],
            'code': code, 'code_verifier': self.verifier if verifier is None else verifier,
        })

    def test_metadata_is_oauth_not_oidc(self):
        data = self.client.get('/.well-known/oauth-authorization-server').get_json()
        self.assertEqual(data['issuer'], 'https://auth.example')
        self.assertEqual(data['code_challenge_methods_supported'], ['S256'])
        self.assertTrue(data['registration_screen_hint_supported'])
        self.assertNotIn('id_token_signing_alg_values_supported', data)

    def test_pkce_exchange_requires_verifier_then_single_use(self):
        self.assertEqual(self.authorize().status_code, 200)
        self.authenticate_for_test()
        response = self.complete()
        code = parse_qs(urlsplit(response.get_json()['redirectUrl']).query)['code'][0]
        self.assertEqual(self.token(code, '').status_code, 400)
        self.assertEqual(self.token(code, 'b' * 43).status_code, 400)
        response = self.token(code)
        self.assertEqual(response.status_code, 200)
        token = response.get_json()['access_token']
        info = self.client.get('/oauth/userinfo', headers={'Authorization': f'Bearer {token}'})
        self.assertEqual(info.get_json()['username'], 'alice')
        self.assertEqual(self.token(code).status_code, 400)
        self.assertEqual(self.complete().status_code, 400)

    def test_complete_rejects_changed_request(self):
        self.authorize()
        self.authenticate_for_test()
        self.assertEqual(self.complete(state='changed').status_code, 400)
        self.assertEqual(self.complete(redirect_uri='https://evil.example').status_code, 400)

    def test_existing_login_session_does_not_authorize_without_ceremony(self):
        self.authorize()
        user = self.store.create_user('alice', b'a' * 32)
        with self.client.session_transaction() as session:
            session['signed_in_user_id'] = user.id
            session['signed_in_session_version'] = user.session_version
        self.assertEqual(self.complete().status_code, 401)

    def test_expired_authorization_is_rejected(self):
        self.authorize()
        self.authenticate_for_test()
        with self.client.session_transaction() as session:
            session['oauth_request'] = {**session['oauth_request'], 'expires_at': int(time.time()) - 1}
        self.assertEqual(self.complete().status_code, 400)

    def test_invalid_pkce_and_missing_state_redirect_as_errors(self):
        for params in ({'code_challenge_method': 'plain'}, {'code_challenge': 'bad'}, {'state': ''}):
            response = self.authorize(**params)
            self.assertEqual(response.status_code, 302)
            self.assertEqual(parse_qs(urlsplit(response.location).query)['error'], ['invalid_request'])

    def test_closed_registration_never_unlocks(self):
        response = self.authorize(screen_hint='signup', login_hint='Alice')
        self.assertEqual(response.status_code, 302)
        self.assertIn('error=access_denied', response.location)
        with self.client.session_transaction() as session:
            self.assertFalse(session.get('registration_unlocked'))

    def test_invalid_client_cannot_unlock_registration(self):
        self.store.set_registration_settings(mode='open', enabled_until=None, default_demo_allowed=False)
        response = self.authorize(screen_hint='signup', login_hint='Alice', redirect_uri='https://evil.example')
        self.assertEqual(response.status_code, 400)
        with self.client.session_transaction() as session:
            self.assertFalse(session.get('registration_unlocked'))

    def test_registration_binds_username_and_continues_authorization(self):
        self.store.set_registration_settings(mode='open', enabled_until=None, default_demo_allowed=False)
        response = self.authorize(screen_hint='signup', login_hint='Alice')
        self.assertEqual(response.status_code, 200)
        self.assertIn('data-screen-hint="signup"', response.get_data(as_text=True))
        self.assertIn('data-error-redirect-uri="https://ppq.example/api/auth/callback"', response.get_data(as_text=True))
        self.assertEqual(self.client.post('/api/register/options', json={'username': 'Mallory', 'oauth': True}).status_code, 400)
        self.assertEqual(self.client.post('/api/register/options', json={'username': 'Alice', 'oauth': True}).status_code, 200)
        result = RegistrationResult(credential_id=b'new-id', public_key=b'new-public-key', sign_count=0,
            aaguid='test', credential_type='public-key', device_type='single_device', backed_up=False,
            transports=['internal'], user_verified=True)
        with patch('jstu_passkey.app.verify_registration', return_value=result):
            self.assertEqual(self.client.post('/api/register/verify', json={'credential': {}}).status_code, 200)
        response = self.complete()
        self.assertEqual(response.status_code, 200)
        code = parse_qs(urlsplit(response.get_json()['redirectUrl']).query)['code'][0]
        self.assertEqual(self.token(code).get_json()['user']['username'], 'Alice')

    def test_registration_gate_is_rechecked_after_page_load(self):
        self.store.set_registration_settings(mode='open', enabled_until=None, default_demo_allowed=False)
        self.authorize(screen_hint='signup', login_hint='Alice')
        self.store.set_registration_settings(mode='closed', enabled_until=None, default_demo_allowed=False)
        self.assertEqual(self.client.post('/api/register/options', json={'username': 'Alice'}).status_code, 403)

    def test_registration_from_an_old_tab_cannot_authorize_new_request(self):
        self.store.set_registration_settings(mode='open', enabled_until=None, default_demo_allowed=False)
        self.authorize(screen_hint='signup', login_hint='Alice')
        self.assertEqual(self.client.post('/api/register/options', json={'username': 'Alice', 'oauth': True}).status_code, 200)
        self.authorize(screen_hint='signup', login_hint='Alice')
        result = RegistrationResult(credential_id=b'old-tab', public_key=b'public-key', sign_count=0,
            aaguid='test', credential_type='public-key', device_type='single_device', backed_up=False,
            transports=['internal'], user_verified=True)
        with patch('jstu_passkey.app.verify_registration', return_value=result):
            self.assertEqual(self.client.post('/api/register/verify', json={'credential': {}}).status_code, 200)
        self.assertEqual(self.complete().status_code, 401)

    def test_root_registration_does_not_complete_pending_oauth(self):
        self.store.set_registration_settings(mode='open', enabled_until=None, default_demo_allowed=False)
        self.authorize(screen_hint='signup', login_hint='Alice')
        self.assertEqual(self.client.post('/api/register/options', json={'username': 'Alice'}).status_code, 200)
        result = RegistrationResult(credential_id=b'root', public_key=b'public-key', sign_count=0,
            aaguid='test', credential_type='public-key', device_type='single_device', backed_up=False,
            transports=['internal'], user_verified=True)
        with patch('jstu_passkey.app.verify_registration', return_value=result):
            self.assertEqual(self.client.post('/api/register/verify', json={'credential': {}}).status_code, 200)
        self.assertEqual(self.complete().status_code, 401)

    def test_login_hint_cannot_be_replaced_by_browser(self):
        self.authorize(login_hint='Alice')
        with self.client.session_transaction() as session:
            flow = session['auth_flow_token']
        response = self.client.post('/auth/passkey/options', json={'mode': 'code', 'username': 'Bob', 'authFlowToken': flow})
        self.assertEqual(response.status_code, 400)

    def test_tampered_wrapped_code_and_plain_code_downgrade_fail(self):
        code = new_authorization_code('key', self.challenge)
        self.assertTrue(verify_code_pkce('key', code, self.verifier, 300))
        self.assertFalse(verify_code_pkce('wrong', code, self.verifier, 300))
        self.assertFalse(verify_code_pkce('key', code + 'x', self.verifier, 300))
        self.assertFalse(verify_code_pkce('key', 'plain-code', self.verifier, 300))
        self.assertFalse(verify_code_pkce('key', code, None, 300))


if __name__ == '__main__':
    unittest.main()
