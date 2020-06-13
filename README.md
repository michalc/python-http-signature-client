# http-signature-client

HTTP client agnostic Python implementation of the client side of the [IETF draft "Signing HTTP Messages"](https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00), with [cryptography](https://github.com/pyca/cryptography) the only dependency other than the Python standard library.

> This is a work in progress. This README serves as a rough design spec.


## Usage

```python
from http_signature_client import sign_ed25519

signed_headers = sign_ed25519(method, url, headers_to_sign, private_key)
```

If the server required a digest of the HTTP body, you must calculate `digest` header and pass it in `headers_to_sign`.


## Recipe: Python Requests with SHA-256 digest of body

```python
from base64 import b64encode
import hashlib
from http_signature_client import sign_ed25519
from requests.auth import AuthBase

class HttpSignature(AuthBase):
    def __init__(self, private_key):
        self.private_key = private_key

    def __call__(self, r):
        digest = b64encode(hashlib.sha256(r.body).digest()).decode('ascii')
        headers_to_sign = r.headers.items() + (('digest', f'SHA-256={digest}'))
        r.headers = dict(sign_ed25519(r.method, r.path_url, headers_to_sign, self.private_key))
        return r

response = requests.post('http://mydomain.test/path', body=b'The bytes',
                         auth=HttpSignature(private_key))
```


## Recipe: Python Requests without digest of body

```python
from http_signature_client import sign_ed25519
from requests.auth import AuthBase

class HttpSignatureWithoutBodyDigest(AuthBase):
    def __init__(self, private_key):
        self.private_key = private_key

    def __call__(self, r):
        r.headers = dict(sign_ed25519(r.method, r.path_url, r.headers.items() , self.private_key))
        return r

response = requests.post('http://mydomain.test/path', body=b'The bytes',
                         auth=HttpSignatureWithoutBodyDigest(private_key))
```
