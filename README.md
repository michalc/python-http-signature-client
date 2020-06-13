# http-signature-client

HTTP client agnostic Python implementation of the client side of the [IETF draft "Signing HTTP Messages"](https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00), with [cryptography](https://github.com/pyca/cryptography) the only dependency other than the Python standard library.

A deliberate subset of the signature algorithm is implemented:

- requests are signed using an Ed25519 private key [currently seen as a good algorithm];
- a SHA-512 digest of the body is required [for the server to authenticate more of the request];
- the algorithm parameter is not sent [it should not be used by the server to choose the algorithm].

> This is a work in progress. This README serves as a rough design spec.


## Usage

```python
from http_signature_client import sign_ed25519_sha512

signed_headers = sign_ed25519_sha512(private_key, method, url, headers_to_sign, body_sha512)
```


## Recipe: Python requests

```python
from base64 import b64encode
import hashlib
from http_signature_client import sign_ed25519_sha512
from requests.auth import AuthBase

class HttpSignature(AuthBase):
    def __init__(self, private_key):
        self.private_key = private_key

    def __call__(self, r):
        body_sha512 = b64encode(hashlib.sha512(r.body).digest()).decode('ascii')
        r.headers = dict(sign_ed25519_sha512(self.private_key, r.method, r.path_url, r.headers.items(), body_sha512))
        return r

response = requests.post('http://mydomain.test/path', data=b'The bytes',
                         auth=HttpSignature(private_key))
```
