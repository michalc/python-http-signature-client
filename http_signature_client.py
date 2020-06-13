from base64 import b64encode
from collections import defaultdict
from datetime import datetime


def sign(key_id, private_key, method, path, headers_to_sign):
    created = str(int(datetime.now().timestamp()))

    def canonical_headers():
        headers_lists = defaultdict(list)
        for key, value in headers_to_sign:
            headers_lists[key.strip().lower()].append(value)
        return tuple((key, ', '.join(values)) for key, values in headers_lists.items())

    signature_input = (
        ('(request-target)', f'{method} {path}'),
        ('(created)', created),
    ) + canonical_headers()

    signature = b64encode(private_key.sign('\n'.join(
        f'{key}: {value}' for key, value in signature_input
    ).encode('ascii'))).decode('ascii')

    headers = ' '.join(key for key, _ in signature_input)
    authorization = \
        f'Signature: keyId="{key_id}", created={created}, headers="{headers}, ' \
        f'signature="{signature}"'

    return (('authorization', authorization),) + headers_to_sign
