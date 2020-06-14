from base64 import b64encode
from collections import defaultdict
from datetime import datetime
from typing import Callable, DefaultDict, FrozenSet, List, Tuple


def sign_headers(
        key_id: str, sign: Callable[[bytes], bytes], method: str, path: str,
        headers_to_sign: Tuple[Tuple[str, str], ...],
        headers_to_ignore: FrozenSet[str] = frozenset(('keep-alive',
                                                       'transfer-encoding', 'connection'))) \
        -> Tuple[Tuple[str, str], ...]:
    method_lower = method.lower()
    created = str(int(datetime.now().timestamp()))

    def canonical_headers() -> Tuple[Tuple[str, str], ...]:
        headers_lists: DefaultDict[str, List[str]] = defaultdict(list)
        for key, value in headers_to_sign:
            key_lower = key.lower()
            if key_lower not in headers_to_ignore:
                headers_lists[key_lower].append(value.strip())
        return tuple((key, ', '.join(values)) for key, values in headers_lists.items())

    signature_input = (
        ('(request-target)', f'{method_lower} {path}'),
        ('(created)', created),
    ) + canonical_headers()

    signature = b64encode(sign('\n'.join(
        f'{key}: {value}' for key, value in signature_input
    ).encode('ascii'))).decode('ascii')

    headers = ' '.join(key for key, _ in signature_input)
    authorization = \
        f'Signature: keyId="{key_id}", created={created}, headers="{headers}", ' \
        f'signature="{signature}"'

    return (('authorization', authorization),) + headers_to_sign
