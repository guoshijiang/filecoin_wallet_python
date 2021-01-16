import json
import sys
import logging
import binascii
import struct
from base64 import b32encode, b32decode
from typing import Union
from hashlib import blake2b
try:
    from io import BytesIO
except ImportError:
    from StringIO import StringIO as BytesIO
from typing import Any, Dict


class Protocol:
    SECP256K1 = 1   # SECP256K1 方式

if sys.version > "3":
    def _byte(b):
        return bytes((b,))
else:
    def _byte(b):
        return chr(b)


def encode(number: int) -> bytes:
    buf = b""
    while True:
        towrite = number & 0x7F
        number >>= 7
        if number:
            buf += _byte(towrite | 0x80)
        else:
            buf += _byte(towrite)
            break
    return buf


def decode_stream(stream: BytesIO) -> int:
    shift = 0
    result = 0
    while True:
        i = _read_one(stream)
        result |= (i & 0x7F) << shift
        shift += 7
        if not (i & 0x80):
            break
    return result


def decode_bytes(buf: bytes) -> int:
    return decode_stream(BytesIO(buf))


def _read_one(stream: BytesIO):
    c = stream.read(1)
    if c == b"":
        raise EOFError("Unexpected EOF while reading bytes")
    return ord(c)


class Blake2bConfig:
    def __init__(self, size: int):
        self.size = size

PayloadHashLength = 20
ChecksumHashLength = 4
MaxAddressStringLength = 2 + 84
MinAddressStringLength = 3
BlsPublicKeyBytes = 48
BlsPrivateKeyBytes = 32
payloadHashConfig = Blake2bConfig(PayloadHashLength)
checksumHashConfig = Blake2bConfig(ChecksumHashLength)
encodeStd = "abcdefghijklmnopqrstuvwxyz234567"


def b2s(b: bytes) -> str:
    if len(b) == 1:
        return str(struct.unpack("b", b)[0])
    return binascii.hexlify(b).decode()


def s2b(s: Union[str, int]) -> bytes:
    if isinstance(s, int):
        return struct.pack("b", s)
    return binascii.unhexlify(s)


def _hash(ingest: bytes, config: Blake2bConfig) -> bytes:
    return blake2b(ingest, digest_size=config.size).digest()


def address_hash(ingest: bytes) -> bytes:
    return _hash(ingest, payloadHashConfig)


def checksum(ingest: bytes) -> bytes:
    return _hash(ingest, checksumHashConfig)


def validate_checksum(ingest: bytes, expect: bytes) -> bool:
    return checksum(ingest) == expect


def address_encode(ingest: bytes) -> str:
    return b32encode(ingest).decode().lower().rstrip("=")


def _b32_padding(s: str):
    return s + ("=" * (8 - (len(s) % 8)))


def address_decode(ingest: str) -> bytes:
    return b32decode(_b32_padding(ingest.upper()))


def privkey_param(type: str, priv_key: str):
    privk = Dict[str, Any] = {
        'Type': type,
        'PrivateKey': priv_key,
    }
    return json.dumps(privk, separators=(",", ":"))