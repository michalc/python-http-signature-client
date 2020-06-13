# http-signature-client

HTTP client agnostic Python implementation of the client side of the [IETF draft "Signing HTTP Messages"](https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00). No dependencies other than the standard library, but [cryptography](https://github.com/pyca/cryptography) would typically be required in client code to load a private key.

A deliberate subset of the signature algorithm is implemented:

- the expires parameter is not sent [the server can decide this];
- the algorithm parameter is not sent [it should not be used by the server to choose the algorithm].


## Usage

```python
from http_signature_client import sign_ed25519_sha512

signed_headers = sign(key_id, private_key, method, path, headers_to_sign)
```


## Recipe: Python requests

```python
from base64 import b64encode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import hashlib
from http_signature_client import sign
from requests.auth import AuthBase

class HttpSignatureWithBodyDigest(AuthBase):
    def __init__(self, key_id, pem_private_key):
        self.key_id = key_id
        self.private_key = load_pem_private_key(pem_private_key, password=None, backend=default_backend())

    def __call__(self, r):
        body_sha512 = b64encode(hashlib.sha512(r.body).digest()).decode('ascii')
        headers_to_sign = r.headers.items() + (('digest', f'SHA512={body_sha512}'))
        r.headers = dict(sign_ed25519_sha512(
            self.key_id, self.private_key.sign,
            r.method, r.path, r.headers.items(), body_sha512))
        return r

response = requests.post('http://mydomain.test/path', data=b'The bytes',
                         auth=HttpSignature(key_id, pem_private_key))
```
