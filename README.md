# python-http-signature-client

HTTP client agnostic Python implementation of the client side of the [IETF draft "Signing HTTP Messages"](https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00).

> This is a work in progress. This README serves as a rough design spec.


## Usage

```python
from http_signature_client import sign_ed25519

headers = sign_ed25519(method, url, headers, private_key)
```
