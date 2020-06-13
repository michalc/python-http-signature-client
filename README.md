# http-signature-client

HTTP client agnostic Python implementation of the client side of the [IETF draft "Signing HTTP Messages"](https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00).

> This is a work in progress. This README serves as a rough design spec.


## Usage

```python
from http_signature_client import sign_ed25519

signed_headers = sign_ed25519(method, url, headers_to_sign, private_key)
```

If the server required a digest of the HTTP body, you must calculate `digest` header and pass it in `headers_to_sign`.


## Recipe: Python Requests with SHA-256 digest of body

```python
from http_signature_client import sign_ed25519
from requests.auth import AuthBase

class HttpSignatureEd25519Auth(AuthBase):
    def __init__(self, private_key):
        self.private_key = private_key

    def __call__(self, r):
        r.headers = dict(sign_ed25519(r.method, r.path_url, r.headers.items(), private_key))
        return r
```


## Recipe: Python Requests without digest of body

```python
from http_signature_client import sign_ed25519
from requests.auth import AuthBase

class HttpSignatureEd25519Auth(AuthBase):
    def __init__(self, get_private_key):
        self.get_private_key = get_private_key

    def __call__(self, r):
        r.headers = dict(sign_ed25519(method, url, r.headers.items(), private_key))
        return r
```
