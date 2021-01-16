import hashlib
import binascii
from common.transaction import handle_vrs, get_signature
from secp256k1 import PrivateKey
cid_prefix = bytes([0x01, 0x71, 0xa0, 0xe4, 0x02, 0x20])


def filecoin_sign(ft, pri_key, pub_key):
    digest_cbor = hashlib.blake2b(digest_size=32, key=b"", salt=b"", person=b"")
    digest_cbor.update(ft.cbor_serial())
    digest_sign = hashlib.blake2b(digest_size=32, key=b"", salt=b"", person=b"")
    digest_sign.update(cid_prefix.__add__(digest_cbor.digest()))
    tx_decode = binascii.hexlify(digest_sign.digest()).decode()
    privkey = PrivateKey(bytes(bytearray.fromhex(pri_key)), raw=True)
    sig_check = privkey.ecdsa_sign(bytes(bytearray.fromhex(tx_decode)), raw=True)
    sig_ser = privkey.ecdsa_serialize(sig_check)
    sign_str = sig_ser.hex()
    v, r, s = get_signature(sign_str, tx_decode, pub_key)
    sign_str_h = handle_vrs(v, r, s)
    sign_msg = ft.signed_tx(sign_str_h)
    return sign_msg

