from base64 import b64encode
import hashlib
import unittest

from http.server import HTTPServer, BaseHTTPRequestHandler
import socketserver
import threading


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from freezegun import freeze_time
import requests
import urllib3

from http_signature_client import sign_headers


class TestIntegration(unittest.TestCase):

    def test_with_digest(self):
        key_id = 'my-key'
        pem_prviate_key = \
            b'-----BEGIN PRIVATE KEY-----\n' \
            b'MC4CAQAwBQYDK2VwBCIEINQG5lNt1bE8TZa68mV/WZdpqsXaOXBHvgPQGm5CcjHp\n' \
            b'-----END PRIVATE KEY-----\n'

        private_key = load_pem_private_key(
            pem_prviate_key, password=None, backend=default_backend())
        method = 'post'
        url = '/some-path?a=b&a=c&d=e'
        body_sha512 = b64encode(hashlib.sha512(b'some-data').digest()).decode('ascii')
        headers = (
            ('digest', f'SHA512={body_sha512}'),
            ('x-custom', 'first  '),
            ('x-custom', '  second'),
        )

        with freeze_time('2012-01-14 03:21:34'):
            signed_headers = sign_headers(key_id, private_key.sign, method, url, headers)

        print(signed_headers)
        self.assertEqual(signed_headers, (
            (
                'authorization',
                'Signature: keyId="my-key", created=1326511294, headers="(request-target) '
                '(created) digest x-custom", '
                'signature="rRcnh3PzKV8isZ+4fW7T4aTswbbDT+JGyQ4HtFn8GlxkbHxkRmN5W3HPRlRMSF/NrawTZ+'
                'kXjkFKaUrar0syAw=="',
            ),
            (
                'digest',
                'SHA512=4cT8Z/GQnjUIPMUwn8ujbSdDM6PEAJqUqXBSc+QfyIthia0VdVHj050dqkQSJk0TEgtnE8mdO+'
                'TWTH306npMew==',
            ),
            (
                'x-custom', 'first  ',
            ),
            (
                'x-custom', '  second',
            )
        ))

    def test_requests(self):
        received_headers = None

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                nonlocal received_headers
                received_headers = tuple(self.headers.items())
                self.send_response(200)
                self.end_headers()

        class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
            daemon_threads = True

        server = ThreadingHTTPServer(('0.0.0.0', 8080), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()

        def cleanup():
            server.shutdown()
            thread.join()
        self.addCleanup(cleanup)

        class HttpSignatureWithBodyDigest(requests.auth.AuthBase):
            def __init__(self, key_id, pem_private_key):
                self.key_id = key_id
                self.private_key = load_pem_private_key(
                    pem_private_key, password=None, backend=default_backend())

            def __call__(self, r):
                body_sha512 = b64encode(hashlib.sha512(r.body).digest()).decode('ascii')
                headers_to_sign = tuple(r.headers.items()) + (('digest', f'SHA512={body_sha512}'),)
                parsed_url = urllib3.util.url.parse_url(r.path_url)
                path = parsed_url.path + (f'?{parsed_url.query}' if parsed_url.query else '')
                r.headers = dict(sign_headers(
                    self.key_id, self.private_key.sign, r.method.lower(), path, headers_to_sign))
                return r

        def make_request():
            key_id = 'my-key'
            pem_private_key = \
                b'-----BEGIN PRIVATE KEY-----\n' \
                b'MC4CAQAwBQYDK2VwBCIEINQG5lNt1bE8TZa68mV/WZdpqsXaOXBHvgPQGm5CcjHp\n' \
                b'-----END PRIVATE KEY-----\n'
            requests.post('http://localhost:8080/path?a=b', data=b'The bytes',
                          auth=HttpSignatureWithBodyDigest(key_id, pem_private_key))

        with freeze_time('2012-01-14 03:21:34'):
            make_request()

        self.assertEqual(received_headers, (
            (
                'Host',
                'localhost:8080',
            ),
            (
                'authorization',
                'Signature: keyId="my-key", created=1326511294, headers="(request-target) '
                '(created) user-agent accept-encoding accept connection content-length digest", '
                'signature="IngdVNAhHx5E98AdkeOrkUC0Zy8v1ix2E4rbG0c3i9X3yicHKNKt+uACYntKvNFA5q1q9C'
                'GoG45W63u3JshCDg=="',
            ),
            (
                'User-Agent', 'python-requests/2.23.0',
            ),
            (
                'Accept-Encoding', 'gzip, deflate',
            ),
            (
                'Accept', '*/*',
            ),
            (
                'Connection', 'keep-alive',
            ),
            (
                'Content-Length', '9',
            ),
            (
                'digest',
                'SHA512=Jpu2uP4aOrJMRxr5j9NKiqwK0ksXiftpjdHOGJTU4v7BxYvf/nEYHxeWL7YCsFXE3XJ9q2luOW'
                'XKpCQmDaQxCg==',
            )
        ))
