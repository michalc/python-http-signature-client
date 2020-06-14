from base64 import b64encode
import hashlib
import unittest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from freezegun import freeze_time

from http_signature_client import sign_headers


class TestIntegration(unittest.TestCase):

    def test_no_headers(self):
        key_id = 'my-key'
        private_key = load_pem_private_key(
            TEST_PRIVATE_KEY, password=None, backend=default_backend())
        method = 'post'
        url = '/some-path?a=b&a=c&d=e'
        body_sha512 = b64encode(hashlib.sha512(b'some-data').digest()).decode('ascii')
        headers = (('digest', f'SHA512={body_sha512}'),)

        with freeze_time('2012-01-14 03:21:34'):
            signed_headers = sign_headers(key_id, private_key.sign, method, url, headers)

        self.assertEqual(signed_headers, (
            (
                'authorization',
                'Signature: keyId="my-key", created=1326511294, headers="(request-target) '
                '(created) digest, '
                'signature="hVRwKrNAhELt7cMBx+AKDRLlzKgJp1yKkJHh1HRM/JLlTpJOIWw56Hljpeq9tqXf1zqYWy'
                '25bQ6vYlJeHivTCg=="',
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
