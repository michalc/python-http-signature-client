from base64 import b64encode
import hashlib
import unittest

from freezegun import freeze_time
from http_signature_client import sign_ed25519_sha512


class TestIntegration(unittest.TestCase):

    def test_no_headers(self):
        key_id = 'my-key'
        private_key = TEST_PRIVATE_KEY
        method = 'POST'
        url = '/some-path?a=b&a=c&d=e'
        headers = ()
        body_sha512 = b64encode(hashlib.sha512(b'some-data').digest()).decode('ascii')

        with freeze_time('2012-01-14 03:21:34'):
            signed_headers = sign_ed25519_sha512(
                key_id, private_key, method, url, headers, body_sha512)

        self.assertEqual(signed_headers, (
            (
                'authorization',
                'Signature: keyId="my-key", created=1326511294, headers="(request-target) '
                '(created) digest, '
                'signature="f5rTFUPTfMub+B/F+3f7YoniDXDJRhhf8d7LMYfvUGEMNgIhGYBTj2FezkLY/Sv94c9CNq'
                'cRGhCYifJ106B5Ag=="',
            ),
            (
                'digest',
                'SHA512=4cT8Z/GQnjUIPMUwn8ujbSdDM6PEAJqUqXBSc+QfyIthia0VdVHj050dqkQSJk0TEgtnE8mdO+'
                'TWTH306npMew==',
            )
        ))


TEST_PRIVATE_KEY = \
    b'-----BEGIN PRIVATE KEY-----\n' \
    b'MC4CAQAwBQYDK2VwBCIEINQG5lNt1bE8TZa68mV/WZdpqsXaOXBHvgPQGm5CcjHp\n' \
    b'-----END PRIVATE KEY-----\n'
