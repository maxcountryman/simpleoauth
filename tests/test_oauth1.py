# -*- coding: utf-8 -*-
from base import SimpleOauthTestCase
from simpleoauth.oauth1 import (hmac_sha1_signer, make_auth_header,
                                make_params, OAuth1Error, sign)

import contextlib


@contextlib.contextmanager
def constant_variables(t=0, r=0):
    import simpleoauth.oauth1

    old_time = simpleoauth.oauth1.time
    old_random = simpleoauth.oauth1.random

    simpleoauth.oauth1.time = lambda: t
    simpleoauth.oauth1.random = lambda: r
    yield
    simpleoauth.oauth1.time = old_time
    simpleoauth.oauth1.random = old_random


class OAuth1TestCase(SimpleOauthTestCase):
    maxDiff = None

    def test_hmac_sha1_signer(self):
        with constant_variables():
            sig = hmac_sha1_signer('consumer_secret',
                                   'access_token_secret',
                                   'GET',
                                   'http://example.com/',
                                   {},
                                   {})

            self.assertEqual(sig, 'HpqBQXW13CJcVZ+Nao7nClBajGc=')

    def test_make_params(self):
        with constant_variables():
            params = make_params({},
                                 'consumer_key',
                                 'hmac_sha1_signer',
                                 'access_token')

            expected = \
                {'oauth_consumer_key': 'consumer_key',
                 'oauth_nonce': 'b6589fc6ab0dc82cf12099d1c2d40ab994e8410c',
                 'oauth_signature_method': 'hmac_sha1_signer',
                 'oauth_timestamp': 0,
                 'oauth_token': 'access_token',
                 'oauth_version': '1.0'}

            self.assertEqual(params, expected)

    def test_make_auth_header(self):
        with constant_variables():
            params = make_params({},
                                 'consumer_key',
                                 'hmac_sha1_signer',
                                 'access_token')
            header = make_auth_header(params, 'foo')
            expected = \
                ('OAuth realm="foo",'
                 'oauth_consumer_key="consumer_key",'
                 'oauth_nonce="b6589fc6ab0dc82cf12099d1c2d40ab994e8410c",'
                 'oauth_signature_method="hmac_sha1_signer",'
                 'oauth_timestamp="0",'
                 'oauth_token="access_token",'
                 'oauth_version="1.0"')
            self.assertEqual(header, expected)

    def test_sign(self):
        with constant_variables():
            sig = sign({'params': 'foo=bar'},
                       'http://example.com/',
                       'GET',
                       'consumer_key',
                       'consumer_secret',
                       'access_token',
                       'access_token_secret')

            expected = \
                {'oauth_consumer_key': 'consumer_key',
                 'oauth_nonce': 'b6589fc6ab0dc82cf12099d1c2d40ab994e8410c',
                 'oauth_signature': 'OTdC8apUL3RhM0FvwondSh5bTdo=',
                 'oauth_signature_method': 'HMAC-SHA1',
                 'oauth_timestamp': 0,
                 'oauth_token': 'access_token',
                 'oauth_version': '1.0'}

            self.assertEqual(sig, expected)

    def test_sign_with_dict_params(self):
        with constant_variables():
            sig = sign({'params': {'foo': 'bar'}},
                       'http://example.com/',
                       'GET',
                       'consumer_key',
                       'consumer_secret',
                       'access_token',
                       'access_token_secret')

            expected = \
                {'oauth_consumer_key': 'consumer_key',
                 'oauth_nonce': 'b6589fc6ab0dc82cf12099d1c2d40ab994e8410c',
                 'oauth_signature': 'OTdC8apUL3RhM0FvwondSh5bTdo=',
                 'oauth_signature_method': 'HMAC-SHA1',
                 'oauth_timestamp': 0,
                 'oauth_token': 'access_token',
                 'oauth_version': '1.0'}

            self.assertEqual(sig, expected)

    def test_sign_with_dict_params_encodable(self):
        with constant_variables():
            sig = sign({'params': {'foo+bar': 'baz'}},
                       'http://example.com/',
                       'GET',
                       'consumer_key',
                       'consumer_secret',
                       'access_token',
                       'access_token_secret')

            expected = \
                {'oauth_consumer_key': 'consumer_key',
                 'oauth_nonce': 'b6589fc6ab0dc82cf12099d1c2d40ab994e8410c',
                 'oauth_signature': 'eLMzvTMImpHvm0YVZVW9a4M+N80=',
                 'oauth_signature_method': 'HMAC-SHA1',
                 'oauth_timestamp': 0,
                 'oauth_token': 'access_token',
                 'oauth_version': '1.0'}

            self.assertEqual(sig, expected)

    def test_sign_with_japanese_params(self):
        with constant_variables():
            sig = sign({'params': {u'こんにちは': u'世界'}},
                       'http://example.com/',
                       'GET',
                       'consumer_key',
                       'consumer_secret',
                       'access_token',
                       'access_token_secret')

            expected = \
                {'oauth_consumer_key': 'consumer_key',
                 'oauth_nonce': 'b6589fc6ab0dc82cf12099d1c2d40ab994e8410c',
                 'oauth_signature': 'NCeOE7B7uqZBWBqwWh7ROxLMdM8=',
                 'oauth_signature_method': 'HMAC-SHA1',
                 'oauth_timestamp': 0,
                 'oauth_token': 'access_token',
                 'oauth_version': '1.0'}

            self.assertEqual(sig, expected)

    def test_sign_with_header_auth(self):
        with constant_variables():
            sig = sign({'params': 'foo=bar'},
                       'http://example.com/',
                       'GET',
                       'consumer_key',
                       'consumer_secret',
                       'access_token',
                       'access_token_secret',
                       header_auth=True)

            expected = \
                {'Authorization':
                 ('OAuth realm="",'
                  'oauth_consumer_key="consumer_key",'
                  'oauth_nonce="b6589fc6ab0dc82cf12099d1c2d40ab994e8410c",'
                  'oauth_signature="OTdC8apUL3RhM0FvwondSh5bTdo%3D",'
                  'oauth_signature_method="HMAC-SHA1",'
                  'oauth_timestamp="0",'
                  'oauth_token="access_token",'
                  'oauth_version="1.0"')}

            self.assertEqual(sig, expected)

    def test_sign_with_form_urlencoded(self):
        with constant_variables():
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            sig = sign({'data': 'foo=bar&baz=qux', 'headers': headers},
                       'http://example.com/',
                       'POST',
                       'consumer_key',
                       'consumer_secret',
                       'access_token',
                       'access_token_secret')

            expected = \
                {'oauth_consumer_key': 'consumer_key',
                 'oauth_nonce': 'b6589fc6ab0dc82cf12099d1c2d40ab994e8410c',
                 'oauth_signature': 'PyWiGu5NYkUANiTO8K/RkIOZxlM=',
                 'oauth_signature_method': 'HMAC-SHA1',
                 'oauth_token': 'access_token',
                 'oauth_timestamp': 0,
                 'oauth_version': '1.0'}

            self.assertEqual(sig, expected)

    def test_sign_with_oauth_params(self):
        with constant_variables():
            sig = sign({'params': 'oauth_verifier=verifier'},
                       'http://example.com/',
                       'GET',
                       'consumer_key',
                       'consumer_secret',
                       'access_token',
                       'access_token_secret')

            expected = \
                {'oauth_consumer_key': 'consumer_key',
                 'oauth_nonce': 'b6589fc6ab0dc82cf12099d1c2d40ab994e8410c',
                 'oauth_signature': 't2koRmG0qelgFf1at5p550MI2oI=',
                 'oauth_signature_method': 'HMAC-SHA1',
                 'oauth_timestamp': 0,
                 'oauth_token': 'access_token',
                 'oauth_verifier': 'verifier',
                 'oauth_version': '1.0'}

            self.assertEqual(sig, expected)

    def test_sign_with_oauth_data(self):
        with constant_variables():
            sig = sign({'data': 'oauth_verifier=verifier'},
                       'http://example.com/',
                       'POST',
                       'consumer_key',
                       'consumer_secret',
                       'access_token',
                       'access_token_secret')

            expected = \
                {'oauth_nonce': 'b6589fc6ab0dc82cf12099d1c2d40ab994e8410c',
                 'oauth_timestamp': 0,
                 'oauth_consumer_key': 'consumer_key',
                 'oauth_signature_method': 'HMAC-SHA1',
                 'oauth_version': '1.0',
                 'oauth_verifier': 'verifier',
                 'oauth_token': 'access_token',
                 'oauth_signature': 'h6Qc1Cdcr1FHqy+8IrtM8grW9FU='}

            self.assertEqual(sig, expected)

    def test_sign_with_bad_sig_name(self):
        with self.assertRaises(OAuth1Error):
            bogus_signer = lambda: None
            sign({'data': 'oauth_verifier=verifier'},
                 'http://example.com/',
                 'POST',
                 'consumer_key',
                 'consumer_secret',
                 'access_token',
                 'access_token_secret',
                 signer=bogus_signer)
