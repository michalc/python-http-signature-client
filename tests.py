from base64 import b64encode
import hashlib
import unittest

from http.server import HTTPServer, BaseHTTPRequestHandler
import socketserver
import threading


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from freezegun import freeze_time
import httpx
import requests
import urllib3

from http_signature_client import sign_headers


class TestIntegration(unittest.TestCase):

    def test_with_digest(self):
        key_id = 'my-key'
        pem_private_key = \
            b'-----BEGIN PRIVATE KEY-----\n' \
            b'MC4CAQAwBQYDK2VwBCIEINQG5lNt1bE8TZa68mV/WZdpqsXaOXBHvgPQGm5CcjHp\n' \
            b'-----END PRIVATE KEY-----\n'

        private_key = load_pem_private_key(
            pem_private_key, password=None, backend=default_backend())
        method = 'post'
        url = '/some-path?a=b&a=c&d=e'
        body_sha512 = b64encode(hashlib.sha512(b'some-data').digest()).decode('ascii')
        headers = (
            ('digest', f'SHA512={body_sha512}'),
            ('connection', 'close'),
            ('x-custom', 'first  '),
            ('x-custom', '  second'),
        )

        with freeze_time('2012-01-14 03:21:34'):
            signed_headers = sign_headers(key_id, private_key.sign, method, url, headers)

        correct_authorization = \
            'Signature: keyId="my-key", created=1326511294, headers="(request-target) (created) ' \
            'digest x-custom", signature="rRcnh3PzKV8isZ+4fW7T4aTswbbDT+JGyQ4HtFn8GlxkbHxkRmN5W3' \
            'HPRlRMSF/NrawTZ+kXjkFKaUrar0syAw=="'

        self.assertEqual(signed_headers, (
            (
                'authorization',
                correct_authorization,
            ),
            (
                'digest',
                'SHA512=4cT8Z/GQnjUIPMUwn8ujbSdDM6PEAJqUqXBSc+QfyIthia0VdVHj050dqkQSJk0TEgtnE8mdO+'
                'TWTH306npMew==',
            ),
            (
                'connection', 'close',
            ),
            (
                'x-custom', 'first  ',
            ),
            (
                'x-custom', '  second',
            )
        ))

        headers_same_canonicalisation = (
            ('Digest', f'SHA512={body_sha512}'),
            ('connection', 'keep-alive'),
            ('X-Custom', 'first  '),
            ('x-custom', '  second'),
        )

        with freeze_time('2012-01-14 03:21:34'):
            signed_headers_mixed = sign_headers(key_id, private_key.sign, method, url,
                                                headers_same_canonicalisation)

        self.assertEqual(signed_headers_mixed, (
            (
                'authorization',
                correct_authorization,
            ),
            (
                'Digest',
                'SHA512=4cT8Z/GQnjUIPMUwn8ujbSdDM6PEAJqUqXBSc+QfyIthia0VdVHj050dqkQSJk0TEgtnE8mdO+'
                'TWTH306npMew==',
            ),
            (
                'connection', 'keep-alive',
            ),
            (
                'X-Custom', 'first  ',
            ),
            (
                'x-custom', '  second',
            )
        ))

    def test_requests(self):
        received_headers = ()

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
            server.server_close()
            thread.join()
        self.addCleanup(cleanup)

        def HttpSignatureWithBodyDigest(key_id, pem_private_key):
            private_key = load_pem_private_key(
                pem_private_key, password=None, backend=default_backend())

            def sign(r):
                body_sha512 = b64encode(hashlib.sha512(r.body).digest()).decode('ascii')
                headers_to_sign = tuple(r.headers.items()) + (('digest', f'SHA512={body_sha512}'),)
                parsed_url = urllib3.util.url.parse_url(r.path_url)
                path = parsed_url.path + (f'?{parsed_url.query}' if parsed_url.query else '')
                r.headers = dict(sign_headers(
                    key_id, private_key.sign, r.method, path, headers_to_sign))
                return r

            return sign

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

        received_headers_dict = dict((key.lower(), value) for key, value in received_headers)
        self.assertEqual(received_headers_dict, {
            'host': 'localhost:8080',
            'authorization': 'Signature: keyId="my-key", created=1326511294, '
                             'headers="(request-target) (created) user-agent accept-encoding '
                             'accept content-length digest", signature="3xG3OmL3Edy62McmHf6aXhvrcC'
                             'P3J9isR8yMA6tIjdyoe8vQz9PJP8AF8oLUzmcVO/dvG/F0zCCAoAah1FTkDg=="',
            'user-agent': 'python-requests/2.23.0',
            'accept-encoding': 'gzip, deflate',
            'accept': '*/*',
            'connection': 'keep-alive',
            'content-length': '9',
            'digest': 'SHA512=Jpu2uP4aOrJMRxr5j9NKiqwK0ksXiftpjdHOGJTU4v7BxYvf/nEYHxeWL7YCsFXE3XJ9'
                      'q2luOWXKpCQmDaQxCg=='
        })

    def test_httpx(self):
        self.maxDiff = 10000
        received_headers = ()

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                nonlocal received_headers
                received_headers = tuple(self.headers.items())
                self.send_response(200)
                self.send_header('content-length', '0')
                self.end_headers()

        class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
            daemon_threads = True

        server = ThreadingHTTPServer(('0.0.0.0', 8080), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()

        def cleanup():
            server.shutdown()
            server.server_close()
            thread.join()
        self.addCleanup(cleanup)

        class HttpSignatureWithBodyDigest(httpx.Auth):
            requires_request_body = True

            def __init__(self, key_id, pem_private_key):
                self.key_id = key_id
                self.private_key = load_pem_private_key(
                    pem_private_key, password=None, backend=default_backend())

            def auth_flow(self, request):
                body_sha512 = b64encode(hashlib.sha512(request.content).digest()).decode('ascii')
                headers_to_sign = tuple(
                    request.headers.items()) + (('digest', f'SHA512={body_sha512}'),)
                request.headers = httpx.Headers(sign_headers(
                    self.key_id, self.private_key.sign, request.method,
                    request.url.full_path, headers_to_sign))
                yield request

        def make_request():
            key_id = 'my-key'
            pem_private_key = \
                b'-----BEGIN PRIVATE KEY-----\n' \
                b'MC4CAQAwBQYDK2VwBCIEINQG5lNt1bE8TZa68mV/WZdpqsXaOXBHvgPQGm5CcjHp\n' \
                b'-----END PRIVATE KEY-----\n'
            httpx.post('http://localhost:8080/path?a=b', data=b'The bytes',
                       auth=HttpSignatureWithBodyDigest(key_id, pem_private_key))

        with freeze_time('2012-01-14 03:21:34'):
            make_request()

        received_headers_dict = dict((key.lower(), value) for key, value in received_headers)
        self.assertEqual(received_headers_dict, {
            'host': 'localhost:8080',
            'authorization': 'Signature: keyId="my-key", created=1326511294, '
                             'headers="(request-target) (created) host user-agent accept '
                             'accept-encoding content-length digest", signature="KfvrEdkreYuFQNpCz'
                             'CK2oZJZg3lFM1UZPOjOH8aixLTO0ilBDvcvDk0PMXLd0kj0LpbR2Qy2w/VgOhwqbiqbD'
                             'w=="',
            'user-agent': 'python-httpx/0.13.3',
            'accept-encoding': 'gzip, deflate',
            'accept': '*/*',
            'connection': 'keep-alive',
            'content-length': '9',
            'digest': 'SHA512=Jpu2uP4aOrJMRxr5j9NKiqwK0ksXiftpjdHOGJTU4v7BxYvf/nEYHxeWL7YCsFXE3XJ9'
                      'q2luOWXKpCQmDaQxCg=='
        })
