# http-signature-client

HTTP client agnostic Python implementation of the client side of the [IETF draft "Signing HTTP Messages"](https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00), with [cryptography](https://github.com/pyca/cryptography) the only dependency other than the Python standard library.

> This is a work in progress. This README serves as a rough design spec.


## Usage

```python
from http_signature_client import sign_ed25519_sha512

# Sign using an ED25519 private key, including a base64 encoded SHA-512 digest of the request body
signed_headers = sign_ed25519_sha512(method, url, headers_to_sign, body_sha512, private_key)
```


## Recipe: Python Requests with SHA-512 digest of body

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
        r.headers = dict(sign_ed25519_sha512(r.method, r.path_url, headers_to_sign, body_sha512, self.private_key))
        return r

response = requests.post('http://mydomain.test/path', data=b'The bytes',
                         auth=HttpSignature(private_key))
```
