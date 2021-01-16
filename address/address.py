from typing import Union
from common.helper import (
    s2b, address_encode, address_hash, checksum, b2s
)

def pubkey_to_address(pubkey: Union[bytes, str]):
    network_prefix = 'f'
    spec256k1_address_mark = 1
    if isinstance(pubkey, str):
        pubkey = s2b(pubkey)
    buf = s2b(1) + address_hash(pubkey)
    check_payload = checksum(s2b(int(b2s(buf[:1]))) + buf[1:])
    addr_str = (
        f"{network_prefix}"
        f"{spec256k1_address_mark}"
        f"{address_encode(buf[1:] + check_payload)}"
    )
    return addr_str
