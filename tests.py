from base64 import b64encode
import hashlib
import unittest

from http.server import HTTPServer, BaseHTTPRequestHandler
import socketserver
import threading

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
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
            'Signature: keyId="my-key", created=1326511294, headers="(created) (request-target) ' \
            'digest x-custom", signature="LiZ968GglNEGaEYcyyYM9TIQ6Z7I2DqYw3T0WfJuDOk27UW0XCQ70p' \
            '3fmg2ju0EsyGDcLeA66DzUQR5YcpTDDA=="'

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
                             'headers="(created) (request-target) user-agent accept-encoding '
                             'accept content-length digest", signature="5E9AExVYVmMLQetvKgF1HkE394'
                             'fF90X0oaazWIoM1wAIfPCi7En658gIhrEfnJ9FHm/zt2loSG6RVGtMma3HDQ=="',
            'user-agent': 'python-requests/2.23.0',
            'accept-encoding': 'gzip, deflate',
            'accept': '*/*',
            'connection': 'keep-alive',
            'content-length': '9',
            'digest': 'SHA512=Jpu2uP4aOrJMRxr5j9NKiqwK0ksXiftpjdHOGJTU4v7BxYvf/nEYHxeWL7YCsFXE3XJ9'
                      'q2luOWXKpCQmDaQxCg=='
        })

    def test_httpx(self):
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
                             'headers="(created) (request-target) host user-agent accept '
                             'accept-encoding content-length digest", signature="jgNe5f7OFtQqxhaBU'
                             'bxGedyrEbyPihe/ux/B/B6T0xbkvHnDKPg/bvlINBWDfeM3r0bmlKG9eazjkr10iIIfC'
                             'w=="',
            'user-agent': 'python-httpx/0.13.3',
            'accept-encoding': 'gzip, deflate',
            'accept': '*/*',
            'connection': 'keep-alive',
            'content-length': '9',
            'digest': 'SHA512=Jpu2uP4aOrJMRxr5j9NKiqwK0ksXiftpjdHOGJTU4v7BxYvf/nEYHxeWL7YCsFXE3XJ9'
                      'q2luOWXKpCQmDaQxCg=='
        })

    def test_case_hs2019(self):
        # The test case in the draft specifies SHA-512, however, from trial and error,
        # the given signature must have been generated using SHA-256

        rsa_private_key = \
            b'-----BEGIN RSA PRIVATE KEY-----\n' \
            b'MIIEqAIBAAKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsP\n' \
            b'BRrwWEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsd\n' \
            b'JKFqMGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75\n' \
            b'jfZgkne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKI\n' \
            b'lE0PuKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZ\n' \
            b'SFlQPSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQABAoIBAG/JZuSWdoVHbi56\n' \
            b'vjgCgkjg3lkO1KrO3nrdm6nrgA9P9qaPjxuKoWaKO1cBQlE1pSWp/cKncYgD5WxE\n' \
            b'CpAnRUXG2pG4zdkzCYzAh1i+c34L6oZoHsirK6oNcEnHveydfzJL5934egm6p8DW\n' \
            b'+m1RQ70yUt4uRc0YSor+q1LGJvGQHReF0WmJBZHrhz5e63Pq7lE0gIwuBqL8SMaA\n' \
            b'yRXtK+JGxZpImTq+NHvEWWCu09SCq0r838ceQI55SvzmTkwqtC+8AT2zFviMZkKR\n' \
            b'Qo6SPsrqItxZWRty2izawTF0Bf5S2VAx7O+6t3wBsQ1sLptoSgX3QblELY5asI0J\n' \
            b'YFz7LJECgYkAsqeUJmqXE3LP8tYoIjMIAKiTm9o6psPlc8CrLI9CH0UbuaA2JCOM\n' \
            b'cCNq8SyYbTqgnWlB9ZfcAm/cFpA8tYci9m5vYK8HNxQr+8FS3Qo8N9RJ8d0U5Csw\n' \
            b'DzMYfRghAfUGwmlWj5hp1pQzAuhwbOXFtxKHVsMPhz1IBtF9Y8jvgqgYHLbmyiu1\n' \
            b'mwJ5AL0pYF0G7x81prlARURwHo0Yf52kEw1dxpx+JXER7hQRWQki5/NsUEtv+8RT\n' \
            b'qn2m6qte5DXLyn83b1qRscSdnCCwKtKWUug5q2ZbwVOCJCtmRwmnP131lWRYfj67\n' \
            b'B/xJ1ZA6X3GEf4sNReNAtaucPEelgR2nsN0gKQKBiGoqHWbK1qYvBxX2X3kbPDkv\n' \
            b'9C+celgZd2PW7aGYLCHq7nPbmfDV0yHcWjOhXZ8jRMjmANVR/eLQ2EfsRLdW69bn\n' \
            b'f3ZD7JS1fwGnO3exGmHO3HZG+6AvberKYVYNHahNFEw5TsAcQWDLRpkGybBcxqZo\n' \
            b'81YCqlqidwfeO5YtlO7etx1xLyqa2NsCeG9A86UjG+aeNnXEIDk1PDK+EuiThIUa\n' \
            b'/2IxKzJKWl1BKr2d4xAfR0ZnEYuRrbeDQYgTImOlfW6/GuYIxKYgEKCFHFqJATAG\n' \
            b'IxHrq1PDOiSwXd2GmVVYyEmhZnbcp8CxaEMQoevxAta0ssMK3w6UsDtvUvYvF22m\n' \
            b'qQKBiD5GwESzsFPy3Ga0MvZpn3D6EJQLgsnrtUPZx+z2Ep2x0xc5orneB5fGyF1P\n' \
            b'WtP+fG5Q6Dpdz3LRfm+KwBCWFKQjg7uTxcjerhBWEYPmEMKYwTJF5PBG9/ddvHLQ\n' \
            b'EQeNC8fHGg4UXU8mhHnSBt3EA10qQJfRDs15M38eG2cYwB1PZpDHScDnDA0=\n' \
            b'-----END RSA PRIVATE KEY-----\n'

        private_key = load_pem_private_key(
            rsa_private_key, password=None, backend=default_backend())

        def sign(data):
            return private_key.sign(
                data,
                padding=padding.PKCS1v15(),
                algorithm=hashes.SHA256(),
            )

        path = '/foo?param=value&pet=dog'
        headers = (
            ('host', 'example.com'),
            ('date', 'Tue, 07 Jun 2014 20:51:35 GMT'),
            ('content-type', 'application/json'),
            ('digest', 'SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE='),
            ('content-length', '18'),
        )

        with freeze_time('2014-06-07 19:51:35 UTC'):
            signed_headers = sign_headers('test-key-a', sign, 'POST', path, headers)

        auth_header = dict(signed_headers)['authorization']

        expected_signature = \
            'KXUj1H3ZOhv3Nk4xlRLTn4bOMlMOmFiud3VXrMa9MaLCxnVmrqOX5BulRvB65YW/wQp0o' \
            'T/nNQpXgOYeY8ovmHlpkRyz5buNDqoOpRsCpLGxsIJ9cX8XVsM9jy+Q1+RIlD9wfWoPHh' \
            'qhoXt35ZkasuIDPF/AETuObs9QydlsqONwbK+TdQguDK/8Va1Pocl6wK1uLwqcXlxhPEb' \
            '55EmdYB9pddDyHTADING7K4qMwof2mC3t8Pb0yoLZoZX5a4Or4FrCCKK/9BHAhq/RsVk0' \
            'dTENMbTB4i7cHvKQu+o9xuYWuxyvBa0Z6NdOb0di70cdrSDEsL5Gz7LBY5J2N9KdGg=='
        expected_auth_header = \
            f'Signature: keyId="test-key-a", created=1402170695, ' \
            f'headers="(created) (request-target) host date content-type digest content-length"' \
            f', signature="{expected_signature}"'

        self.assertEqual(expected_auth_header, auth_header)
