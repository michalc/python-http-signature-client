# http-signature-client  [![CircleCI](https://circleci.com/gh/michalc/python-http-signature-client.svg?style=shield)](https://circleci.com/gh/michalc/python-http-signature-client) [![Test Coverage](https://api.codeclimate.com/v1/badges/fcf6ed3ac0c04d3878a8/test_coverage)](https://codeclimate.com/github/michalc/python-http-signature-client/test_coverage)

Utility function with an HTTP client agnostic Python implementation of the client side of the [IETF draft "Signing HTTP Messages"](https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00). No dependencies other than the standard library, but [cryptography](https://github.com/pyca/cryptography) would typically be required in client code to load a private key.


## Usage

```python
from http_signature_client import sign_headers

signed_headers = sign_headers(key_id, sign, method, path, headers_to_sign)
```


## Recipe: Python requests with PEM-encoded private key and SHA-512 body digest

```python
from base64 import b64encode
import hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import requests
import urllib3

from http_signature_client import sign_headers

class HttpSignatureWithBodyDigest(request.auth.AuthBase):
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
            self.key_id, self.private_key.sign, r.method, path, headers_to_sign))
        return r

# In real cases, take credentials from environment variables/secret store
response = requests.post('http://mydomain.test/path', data=b'The bytes', auth=HttpSignature(
    key_id='my-key',
    pem_private_key= \
        b'-----BEGIN PRIVATE KEY-----\n' \
        b'MC4CAQAwBQYDK2VwBCIEINQG5lNt1bE8TZa68mV/WZdpqsXaOXBHvgPQGm5CcjHp\n' \
        b'-----END PRIVATE KEY-----\n',
    )
)
```


## Recipe: Create an Ed25519 public/private key pair

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

private_key = Ed25519PrivateKey.generate()
print(private_key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()))
print(private_key.public_key().public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo))
```


## What's implemented

A deliberate subset of the signature algorithm is implemented:

- the `request-target` pseudo-header is signed [to allow the server to verify the method and path]
- the `created` pseudo-header is signed [to allow the server to decide to reject if the skew is too large]
- the `headers` parameter is sent [to allow the server to verify headers and pseudo-headers]
- the `expires` parameter is _not_ sent [the server can decide this using the created parameter];
- the `algorithm` parameter is _not_ sent [it should not be used by the server to choose the algorithm].

Note _not_ all headers passed as the `headers_to_sign` parameter are signed by default: common hop-by-hop headers are ignored, since they typically won't make it to the target server unchanged. To customise this list of ignored headers, override the `headers_to_ignore` parameter.
