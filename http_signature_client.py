from base64 import b64encode
from collections import defaultdict
from datetime import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def sign_ed25519_sha512(key_id, pem_private_key, method, path, headers_to_sign, body_sha512):
    private_key = load_pem_private_key(pem_private_key, password=None, backend=default_backend())

    created = str(int(datetime.now().timestamp()))
    digest = f'SHA512={body_sha512}'

    def canonical_headers():
        headers_lists = defaultdict(list)
        for key, value in headers_to_sign:
            headers_lists[key.strip().lower()].append(value)
        return tuple((key, ', '.join(values)) for key, values in headers_lists.items())

    signature_input = (
        ('(request-target)', f'{method} {path}'),
        ('(created)', created),
        ('digest', digest),
    ) + canonical_headers()

    signature = b64encode(private_key.sign('\n'.join(
        f'{key}: {value}' for key, value in signature_input
    ).encode('ascii'))).decode('ascii')

    headers = ' '.join(key for key, _ in signature_input)
    authorization = \
        f'Signature: keyId="{key_id}", created={created}, headers="{headers}, ' \
        f'signature="{signature}"'

    return (('authorization', authorization), ('digest', digest)) + headers_to_sign
