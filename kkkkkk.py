# =============================================================================
# PUBG MOBILE PAK TOOL v4.2 - Termux Optimized (FULLY FIXED)
# Copyright © HASSAN. All rights reserved.
# Supports all PUBG Mobile 4.2 versions
# =============================================================================

import os
import subprocess
import ssl
import urllib.request
import datetime
import itertools as it
import math
import struct
try:
    import const
except ImportError:
    # Define const if it's missing, for basic functionality
    class const:
        CM_MASK = 15
import zlib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import PurePath, Path
import shutil
import getpass
import glob

try:
    import gmalg
    from Crypto.Cipher import AES
    from Crypto.Cipher.AES import MODE_CBC
    from Crypto.Hash import SHA1
    from Crypto.Util.Padding import unpad, pad
    from zstandard import ZstdDecompressor, ZstdCompressor, ZstdCompressionDict, DICT_TYPE_AUTO
except ImportError as e:
    print(f"Error: A required library is missing: {e.name}")
    print("Please install the required libraries using pip.")
    print("Example: pip install pycryptodome zstandard gmalg")
    sys.exit(1)


import time
import sys
from typing import List, Tuple, Optional

ZUC_KEY = bytes.fromhex('01010101010101010101010101010101')
ZUC_IV = bytes.fromhex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')

RSA_MOD_1 = bytes.fromhex(
    'CBE8B9F2504050EF9831B719E9A6249A6D238505ADE909BDE78C180DED6072A0C3347B8AF4780E1F212D952D82D4BF7F233C1ECA499E1F9D9A85B4FAD759F54BABC1666C5DE411EA9E4B2374425DD6C6F54333BBC8F2610FE6063E4D0D6C21A671A8F7C3740555E5DC06D4E1691C456DB4116C0C012BF7B206E8311AAAEC689952BF804EF638F09D5822B4117B114208F14DEB459E80CB770E5B0D7978E21F5E6CED4999D3583108221A7AB28B960277ADB5690A332784019D9C195BE4EA9EA0A09459010F236465DE0D59C3EF7324E954E1118D93EE19F299760C2CDB963CE87973EA5ECC9BBE81C27D4C7C8572AC07E9BCEAC9BD72AB7A56A3C0AD736ABCE4')
RSA_MOD_2 = bytes.fromhex(
    '7F58E8A39A4DA4E87357DDD650EAA16D3B5CE95B213D1030A662566444796A78A84AE9AC3DBFFDE7F41094896696835DAF13B89E6EC2B84963B1B1BAF7151DA245C3FBFAE2A6AE18B2684D03F9229DE2C91440F2A3A3BCDE1E5680C16722A88039C73560D5D43F4B6562C2EEA5B1D926D86B51108A2643C70FB74D6442CE3A08339B8FD8F660AE88129B7AB8C46F2FA58124485CCCB1E987B05A6DA65A01858ED3F89905449AE42BB07290FCB9994BF22E26610BCABB9804783A3B9587917F3D97316EDDA15C5E13F79066407B55A93B291B68A4AC42A98D6E35FED84B14A792D154E62028DDAD20FC301951E5924BE9AD62FB719DD94CC30CAB871BEC4377A8')

SIMPLE1_DECRYPT_KEY = 0x79

SIMPLE2_DECRYPT_KEY = bytes.fromhex('E55B4ED1')
SIMPLE2_BLOCK_SIZE = 16

SM4_SECRET_4 = 'eb691efea914241317a8'
SM4_SECRET_2 = 'Q0hVTKey$as*1ZFlQCiA'
SM4_SECRET_NEW = [
    'xG2qW5lP7lV2iN5fN5pG',
    'xT1cJ6dL5wC0kK1rB4dK',
    'qC4jS5bZ6fL5xE6nD4zA',
    'gD4jQ2aL3bS3lC3xT0iW',
    'xU1yQ8wE9zY3gZ3bT5aE',
    'uQ3cO2dX7xY4xU7gH7iS',
    'gW1fR0jK6wQ4oN0oK1kZ',
    'aJ4pV7iZ7pU4wP2aC2cZ',
    'cX6jT3cM2oT3vK0kJ1qN',
    'iT2vS0cS6yT6cZ1sE1lO'
]

EM_SIMPLE1 = 1
EM_SIMPLE2 = 16
EM_SM4_2 = 2
EM_SM4_4 = 4
EM_SM4_NEW_BASE = 31
EM_SM4_NEW_MASK = ~EM_SM4_NEW_BASE

CM_NONE = 0
CM_ZLIB = 1
CM_ZSTD = 6
CM_ZSTD_DICT = 8
CM_MASK = 15

from gmalg.base import BlockCipher
from gmalg.errors import IncorrectLengthError
from gmalg.utils import ROL32

_S_BOX = bytes([
    0x34, 0x66, 0x25, 0x74, 0x89, 0x78, 0xE4, 0xA9, 0x5A, 0x41, 0xBC, 0x7A, 0xD6, 0x16, 0x21, 0x23,
    0x4D, 0x61, 0xDA, 0x94, 0x9B, 0xDF, 0x13, 0x3C, 0x69, 0x3A, 0x31, 0x0A, 0x5F, 0xD7, 0x99, 0x95,
    0xF1, 0xAE, 0x72, 0x3D, 0x07, 0x60, 0x24, 0xB6, 0x98, 0xEE, 0xC4, 0xA2, 0x2D, 0x88, 0xDD, 0x8D,
    0x04, 0xEA, 0xBB, 0x11, 0xCA, 0x3E, 0x5D, 0xA1, 0xF6, 0x3F, 0xB0, 0x97, 0x80, 0x47, 0x2B, 0xA6,
    0xE6, 0xF7, 0xD9, 0xB1, 0x59, 0xC0, 0x7C, 0xBE, 0x54, 0x28, 0xB7, 0x7E, 0x4F, 0xF8, 0x43, 0x6E,
    0xA0, 0x50, 0x0E, 0xF5, 0x90, 0xB8, 0xFB, 0xA3, 0x7B, 0x62, 0x19, 0x46, 0x03, 0x2A, 0xB9, 0x8F,
    0x9F, 0x77, 0xB4, 0x5B, 0x83, 0x87, 0x08, 0xEB, 0xE2, 0x1E, 0x42, 0xF0, 0x0F, 0xE8, 0x71, 0x6A,
    0x75, 0xAD, 0x55, 0x1F, 0xB5, 0xAB, 0x33, 0xFA, 0x7F, 0x15, 0xBD, 0x85, 0xD8, 0x06, 0x68, 0xB3,
    0x52, 0x30, 0x48, 0x0B, 0x00, 0xED, 0xEF, 0xB2, 0x57, 0x8E, 0xE7, 0x6C, 0xD5, 0xE5, 0x2E, 0x53,
    0x82, 0x05, 0xF9, 0x81, 0xF4, 0x56, 0xBF, 0x8C, 0x4B, 0xE3, 0xDB, 0x4A, 0x91, 0x4C, 0x2C, 0xD3,
    0x40, 0x29, 0x4E, 0x20, 0x14, 0x36, 0x79, 0x09, 0x6F, 0xD1, 0x37, 0xE0, 0x39, 0x0C, 0x8A, 0x92,
    0x38, 0x12, 0x35, 0x6D, 0xE1, 0xFD, 0x93, 0x9A, 0x17, 0xD4, 0xC9, 0x9C, 0x6B, 0x84, 0x26, 0x9D,
    0xAF, 0x76, 0xC1, 0x9E, 0xD0, 0x96, 0xC5, 0xCB, 0xE9, 0x73, 0x49, 0xD2, 0xCD, 0x64, 0xC3, 0xC7,
    0x01, 0x7D, 0xF3, 0xAC, 0xFC, 0xDE, 0xA4, 0x44, 0x32, 0x1B, 0xC2, 0xBA, 0x1C, 0x02, 0xC6, 0x27,
    0x45, 0x8B, 0xF2, 0x18, 0xA7, 0x10, 0x51, 0x1D, 0xC8, 0xCF, 0x63, 0xFF, 0x2F, 0x0D, 0x58, 0xCE,
    0x65, 0xA5, 0xDC, 0x1A, 0x3B, 0x86, 0xFE, 0x22, 0x5C, 0xA8, 0x5E, 0x67, 0xAA, 0xEC, 0x70, 0xCC
])

_FK = [
    0x46970E9C, 0x4BC0685E, 0x59056186, 0xBCA2491E
]

_CK = [
    0x000EB92B, 0x3A0AE783, 0x9E3B5C67, 0xADDBDABF, 0x7B7484CB, 0x49156C63, 0xC79AB5E7, 0x79EC9CFF,
    0x1725BEAB, 0x2FB89CA3, 0x24808AD7, 0xDDD28B1F, 0x4740DA4B, 0xBBC3EA73, 0x247B30E7, 0x91BE385F,
    0x0401248B, 0x45FCD3A3, 0x530B4CE7, 0xC68DD35F, 0xE3D16C2B, 0x4F698C13, 0x6B92C747, 0x769EFB1F,
    0x4C73BE9B, 0xC942B193, 0xAD80D827, 0x372FB33F, 0x13CB6AAB, 0x2BDC0AA3, 0x17A4A247, 0xD5E96CAF
]


def _BS(X):
    return ((_S_BOX[(X >> 24) & 0xff] << 24) |
            (_S_BOX[(X >> 16) & 0xff] << 16) |
            (_S_BOX[(X >> 8) & 0xff] << 8) |
            (_S_BOX[X & 0xff]))


def _T0(X):
    X = _BS(X)
    return X ^ ROL32(X, 2) ^ ROL32(X, 10) ^ ROL32(X, 18) ^ ROL32(X, 24)


def _T1(X):
    X = _BS(X)
    return X ^ ROL32(X, 13) ^ ROL32(X, 23)


def _key_expand(key: bytes, rkey: List[int]):
    K0 = int.from_bytes(key[0:4], "big") ^ _FK[0]
    K1 = int.from_bytes(key[4:8], "big") ^ _FK[1]
    K2 = int.from_bytes(key[8:12], "big") ^ _FK[2]
    K3 = int.from_bytes(key[12:16], "big") ^ _FK[3]

    for i in range(0, 32, 4):
        K0 = K0 ^ _T1(K1 ^ K2 ^ K3 ^ _CK[i])
        rkey[i] = K0
        K1 = K1 ^ _T1(K2 ^ K3 ^ K0 ^ _CK[i + 1])
        rkey[i + 1] = K1
        K2 = K2 ^ _T1(K3 ^ K0 ^ K1 ^ _CK[i + 2])
        rkey[i + 2] = K2
        K3 = K3 ^ _T1(K0 ^ K1 ^ K2 ^ _CK[i + 3])
        rkey[i + 3] = K3


class SM4(BlockCipher):
    @classmethod
    def key_length(self) -> int:
        return 16

    @classmethod
    def block_length(self) -> int:
        return 16

    def __init__(self, key: bytes) -> None:
        if len(key) != self.key_length():
            raise IncorrectLengthError("Key", f"{self.key_length()} bytes", f"{len(key)} bytes")

        self._key: bytes = key
        self._rkey: List[int] = [0] * 32
        _key_expand(self._key, self._rkey)

        self._block_buffer = bytearray()

    def encrypt(self, block: bytes) -> bytes:
        if len(block) != self.block_length():
            raise IncorrectLengthError("Block", f"{self.block_length()} bytes", f"{len(block)} bytes")

        RK = self._rkey

        X0 = int.from_bytes(block[0:4], "big")
        X1 = int.from_bytes(block[4:8], "big")
        X2 = int.from_bytes(block[8:12], "big")
        X3 = int.from_bytes(block[12:16], "big")

        for i in range(0, 32, 4):
            X0 = X0 ^ _T0(X1 ^ X2 ^ X3 ^ RK[i])
            X1 = X1 ^ _T0(X2 ^ X3 ^ X0 ^ RK[i + 1])
            X2 = X2 ^ _T0(X3 ^ X0 ^ X1 ^ RK[i + 2])
            X3 = X3 ^ _T0(X0 ^ X1 ^ X2 ^ RK[i + 3])

        BUFFER = self._block_buffer
        BUFFER.clear()
        BUFFER.extend(X3.to_bytes(4, "big"))
        BUFFER.extend(X2.to_bytes(4, "big"))
        BUFFER.extend(X1.to_bytes(4, "big"))
        BUFFER.extend(X0.to_bytes(4, "big"))
        return bytes(BUFFER)

    def decrypt(self, block: bytes) -> bytes:
        if len(block) != self.block_length():
            raise IncorrectLengthError("Block", f"{self.block_length()} bytes", f"{len(block)} bytes")

        RK = self._rkey

        X0 = int.from_bytes(block[0:4], "big")
        X1 = int.from_bytes(block[4:8], "big")
        X2 = int.from_bytes(block[8:12], "big")
        X3 = int.from_bytes(block[12:16], "big")

        for i in range(0, 32, 4):
            X0 = X0 ^ _T0(X1 ^ X2 ^ X3 ^ RK[31 - i])
            X1 = X1 ^ _T0(X2 ^ X3 ^ X0 ^ RK[30 - i])
            X2 = X2 ^ _T0(X3 ^ X0 ^ X1 ^ RK[29 - i])
            X3 = X3 ^ _T0(X0 ^ X1 ^ X2 ^ RK[28 - i])

        BUFFER = self._block_buffer
        BUFFER.clear()
        BUFFER.extend(X3.to_bytes(4, "big"))
        BUFFER.extend(X2.to_bytes(4, "big"))
        BUFFER.extend(X1.to_bytes(4, "big"))
        BUFFER.extend(X0.to_bytes(4, "big"))
        return bytes(BUFFER)

class Misc:
    @staticmethod
    def pad_to_n(data: bytes, n: int) -> bytes:
        assert n > 0
        padding = n - (len(data) % n)
        if padding == n:
            return data
        return data + b'\x00' * padding

    @staticmethod
    def align_up(x: int, n: int) -> int:
        return ((x + n - 1) // n) * n


class Reader:
    def __init__(self, buffer, cursor=0):
        self._buffer = buffer
        self._cursor = cursor

    def u1(self, move_cursor=True) -> int:
        return self.unpack('B', move_cursor=move_cursor)[0]

    def u4(self, move_cursor=True) -> int:
        return self.unpack('<I', move_cursor=move_cursor)[0]

    def u8(self, move_cursor=True) -> int:
        return self.unpack('<Q', move_cursor=move_cursor)[0]

    def i1(self, move_cursor=True) -> int:
        return self.unpack('b', move_cursor=move_cursor)[0]

    def i4(self, move_cursor=True) -> int:
        return self.unpack('<i', move_cursor=move_cursor)[0]

    def i8(self, move_cursor=True) -> int:
        return self.unpack('<q', move_cursor=move_cursor)[0]

    def s(self, n: int, move_cursor=True) -> bytes:
        return self.unpack(f'{n}s', move_cursor=move_cursor)[0]

    def unpack(self, f: str | bytes, offset=0, move_cursor=True):
        x = struct.unpack_from(f, self._buffer, self._cursor + offset)
        if move_cursor:
            self._cursor += struct.calcsize(f)
        return x

    def string(self, move_cursor=True) -> str:
        length = self.i4(move_cursor=move_cursor)
        if length == 0:
            return str()
        assert length > 0
        offset = 0 if move_cursor else 4
        return self.unpack(f'{length}s', offset=offset, move_cursor=move_cursor)[0].rstrip(b'\x00').decode()


class PakInfo:
    def __init__(self, buffer, keystream: list[int]):
        def decrypt_index_encrypted(x: int) -> int:
            MASK_8 = 0xFF
            return (x ^ keystream[3]) & MASK_8

        def decrypt_magic(x: int) -> int:
            return x ^ keystream[2]

        def decrypt_index_hash(x: bytes) -> bytes:
            key = struct.pack('<5I', *keystream[4:][:5])
            assert len(x) == len(key)
            return bytes(a ^ b for a, b in zip(x, key))

        def decrypt_index_size(x: int) -> int:
            return x ^ ((keystream[10] << 32) | keystream[11])

        def decrypt_index_offset(x: int) -> int:
            return x ^ ((keystream[0] << 32) | keystream[1])

        reader = Reader(buffer[-PakInfo._mem_size(-1):])

        self.index_encrypted: bool = decrypt_index_encrypted(reader.u1()) == 1
        self.magic: int = decrypt_magic(reader.u4())
        self.version: int = reader.u4()
        self.index_hash: bytes = decrypt_index_hash(reader.s(20)) if self.version >= 6 else bytes()
        self.index_size: int = decrypt_index_size(reader.u8())
        self.index_offset: int = decrypt_index_offset(reader.u8())
        if self.version <= 3:
            self.index_encrypted = False

    @staticmethod
    def _mem_size(_: int) -> int:
        return 1 + 4 + 4 + 20 + 8 + 8


class TencentPakInfo(PakInfo):
    def __init__(self, buffer, keystream: list[int]):
        def decrypt_unk(x: bytes) -> bytes:
            key = struct.pack('<8I', *keystream[7:][:8])
            assert len(x) == len(key)
            return bytes(a ^ b for a, b in zip(x, key))

        def decrypt_stem_hash(x: int) -> int:
            return x ^ keystream[8]

        def decrypt_unk_hash(x: int) -> int:
            return x ^ keystream[9]

        super().__init__(buffer, keystream)

        reader = Reader(buffer[-TencentPakInfo._mem_size(self.version):])

        self.unk1: bytes = decrypt_unk(reader.s(32)) if self.version >= 7 else bytes()
        self.packed_key: bytes = reader.s(256) if self.version >= 8 else bytes()
        self.packed_iv: bytes = reader.s(256) if self.version >= 8 else bytes()
        self.packed_index_hash: bytes = reader.s(256) if self.version >= 8 else bytes()
        self.stem_hash: int = decrypt_stem_hash(reader.u4()) if self.version >= 9 else 0
        self.unk2: int = decrypt_unk_hash(reader.u4()) if self.version >= 9 else 0
        self.content_org_hash: bytes = reader.s(20) if self.version >= 12 else bytes()

    @staticmethod
    def _mem_size(version: int) -> int:
        size_for_7 = 32 if version >= 7 else 0
        size_for_8 = 256 * 3 if version >= 8 else 0
        size_for_9 = 4 * 2 if version >= 9 else 0
        size_for_12 = 20 if version >= 12 else 0
        return PakInfo._mem_size(version) + size_for_7 + size_for_8 + size_for_9 + size_for_12


class PakCompressedBlock:
    def __init__(self, reader: Reader):
        self.start: int = reader.u8()
        self.end: int = reader.u8()


@dataclass
class TencentPakEntry:
    def __init__(self, reader: Reader, version: int):
        self.content_hash: bytes = reader.s(20)
        if version <= 1:
            _ = reader.u8()
        self.offset: int = reader.u8()
        self.uncompressed_size: int = reader.u8()
        self.compression_method: int = reader.u4() & CM_MASK
        self.size: int = reader.u8()
        self.unk1: int = reader.u1() if version >= 5 else 0
        self.unk2: bytes = reader.s(20) if version >= 5 else bytes()
        self.compressed_blocks: list[PakCompressedBlock] = [PakCompressedBlock(reader) for _ in range(
            reader.u4())] if self.compression_method != 0 and version >= 3 else []
        self.compression_block_size: int = reader.u4() if version >= 4 else 0
        self.encrypted: bool = reader.u1() == 1 if version >= 4 else False
        self.encryption_method: int = reader.u4() if version >= 12 else 0
        self.index_new_sep: int = reader.u4() if version >= 12 else 0

    def _mem_size(self, version: int) -> int:
        size_for_123 = 20 + 8 + 8 + 4 + 8 + (8 if version == 1 else 0)
        size_for_4 = 4 + 1 if version >= 4 else 0
        size_for_compressed_blocks = 4 + len(self.compressed_blocks) * 16 if self.compressed_blocks else 0
        size_for_5 = 1 + 20 if version >= 5 else 0
        size_for_12 = 4 if version >= 12 else 0
        return size_for_123 + size_for_4 + size_for_5 + size_for_12 + size_for_compressed_blocks


class PakCrypto:
    class _LCG:
        def __init__(self, seed: int):
            self.state = seed

        def next(self) -> int:
            MASK_32 = 0xFFFFFFFF
            MSB_1 = 1 << 31

            def wrap(x: int) -> int:
                x &= MASK_32
                if not x & MSB_1:
                    return x
                else:
                    return ((x + MSB_1) & MASK_32) - MSB_1

            x1 = wrap(0x41C64E6D * self.state)
            self.state = wrap(x1 + 12345)
            x2 = wrap(x1 + 0x13038) if self.state < 0 else self.state
            return ((x2 >> 16) & MASK_32) % 0x7FFF

    @staticmethod
    def zuc_keystream() -> list[int]:
        zuc = gmalg.ZUC(ZUC_KEY, ZUC_IV)
        return [struct.unpack('>I', zuc.generate())[0] for _ in range(16)]

    @staticmethod
    def _xorxor(buffer, x) -> bytes:
        return bytes(buffer[i] ^ x[i % len(x)] for i in range(len(buffer)))

    @staticmethod
    def _hashhash(buffer, n: int) -> bytes:
        result = bytes()
        for i in range(math.ceil(n / SHA1.digest_size)):
            result += SHA1.new(buffer).digest()
        if len(result) >= n:
            result = result[:n]
        else:
            result += b'\x00' * (n - len(result))
        return result

    @staticmethod
    def _meowmeow(buffer) -> bytes:
        def unpad(x):
            skip = 1 + next((i for i in range(len(x)) if x[i] != 0))
            return x[skip:]

        if len(buffer) < 43:
            return bytes()

        x1 = buffer[1:][:SHA1.digest_size]
        x2 = buffer[SHA1.digest_size + 1:]
        x1 = PakCrypto._xorxor(x1, PakCrypto._hashhash(x2, len(x1)))
        x2 = PakCrypto._xorxor(x2, PakCrypto._hashhash(x1, len(x2)))

        part1, m = (x2[:SHA1.digest_size], x2[SHA1.digest_size:])
        if part1 != SHA1.new(b'\x00' * SHA1.digest_size).digest():
            return bytes()

        return unpad(m)

    @staticmethod
    def rsa_extract(signature: bytes, modulus: bytes) -> bytes:
        c = int.from_bytes(signature, 'little')
        n = int.from_bytes(modulus, 'little')
        e = 0x10001
        m = pow(c, e, n).to_bytes(256, 'little').rstrip(b'\x00')
        return PakCrypto._meowmeow(Misc.pad_to_n(m, 4))

    @staticmethod
    def _encrypt_simple1(plaintext) -> bytes:
        return bytes(x ^ SIMPLE1_DECRYPT_KEY for x in plaintext)

    @staticmethod
    def _decrypt_simple1(ciphertext) -> bytes:
        return bytes(x ^ SIMPLE1_DECRYPT_KEY for x in ciphertext)

    @staticmethod
    def _encrypt_simple2(plaintext) -> bytes:
        class RollingKey:
            def __init__(self, initial_value: int):
                self._value = initial_value

            def update(self, x: int) -> int:
                original_value = self._value
                self._value = x
                return original_value ^ x
        
        assert len(plaintext) % SIMPLE2_BLOCK_SIZE == 0
        
        initial_key, = struct.unpack('<I', SIMPLE2_DECRYPT_KEY)
        rolling_key = RollingKey(initial_key)
        ciphertext = (
            struct.pack('<I', rolling_key.update(x)) for x in struct.unpack(f'<{len(plaintext) // 4}I', plaintext)
        )
        return bytes(it.chain.from_iterable(ciphertext))


    @staticmethod
    def _decrypt_simple2(ciphertext) -> bytes:
        class RollingKey:
            def __init__(self, initial_value: int):
                self._value = initial_value

            def update(self, x: int) -> int:
                self._value ^= x
                return self._value

        assert len(ciphertext) % SIMPLE2_BLOCK_SIZE == 0

        initial_key, = struct.unpack('<I', SIMPLE2_DECRYPT_KEY)
        rolling_key = RollingKey(initial_key)
        plaintext = (
            struct.pack('<I', rolling_key.update(x)) for x in struct.unpack(f'<{len(ciphertext) // 4}I', ciphertext)
        )
        return bytes(it.chain.from_iterable(plaintext))

    @staticmethod
    @lru_cache(maxsize=1)
    def _derive_sm4_key(file_path: PurePath, encryption_method: int) -> bytes:
        part1 = file_path.stem.lower()
        if encryption_method == EM_SM4_2:
            secret = SM4_SECRET_2
        elif encryption_method == EM_SM4_4:
            secret = SM4_SECRET_4
        else:
            index = (encryption_method - EM_SM4_NEW_BASE) % len(SM4_SECRET_NEW)
            secret = f'{SM4_SECRET_NEW[index]}{encryption_method}'
        return SHA1.new(str(part1 + secret).encode()).digest()[:SM4.key_length()]

    @staticmethod
    @lru_cache(maxsize=1)
    def _sm4_context_for_key(key: bytes) -> SM4:
        return SM4(key)

    @staticmethod
    def _encrypt_sm4(plaintext, file_path: PurePath, encryption_method: int) -> bytes:
        padded_plaintext = pad(plaintext, SM4.block_length())

        key = PakCrypto._derive_sm4_key(file_path, encryption_method)
        sm4 = PakCrypto._sm4_context_for_key(key)
        return bytes(
            it.chain.from_iterable(
                sm4.encrypt(x) for x in it.batched(padded_plaintext, SM4.block_length())
            )
        )

    @staticmethod
    def _decrypt_sm4(ciphertext, file_path: PurePath, encryption_method: int) -> bytes:
        assert len(ciphertext) % SM4.block_length() == 0

        key = PakCrypto._derive_sm4_key(file_path, encryption_method)
        sm4 = PakCrypto._sm4_context_for_key(key)
        return bytes(
            it.chain.from_iterable(
                sm4.decrypt(x) for x in it.batched(ciphertext, SM4.block_length())
            )
        )


    @staticmethod
    def decrypt_index(ciphertext, pak_info: TencentPakInfo) -> bytes:
        if pak_info.version > 7:
            key = PakCrypto.rsa_extract(pak_info.packed_key, RSA_MOD_1)
            iv = PakCrypto.rsa_extract(pak_info.packed_iv, RSA_MOD_1)
            assert len(key) == 32 and len(iv) == 32

            aes = AES.new(key, MODE_CBC, iv[:16])
            return unpad(aes.decrypt(ciphertext), AES.block_size)
        else:
            return bytes(PakCrypto._decrypt_simple1(ciphertext))


    @staticmethod
    def _is_simple1_method(encryption_method: int) -> bool:
        return encryption_method == EM_SIMPLE1

    @staticmethod
    def _is_simple2_method(encryption_method: int) -> bool:
        return encryption_method == EM_SIMPLE2

    @staticmethod
    def _is_sm4_method(encryption_method: int) -> bool:
        return (encryption_method == EM_SM4_2
                or encryption_method == EM_SM4_4
                or encryption_method & EM_SM4_NEW_MASK != 0)

    @staticmethod
    def align_encrypted_content_size(n: int, encryption_method: int) -> int:
        if PakCrypto._is_simple2_method(encryption_method):
            return Misc.align_up(n, SIMPLE2_BLOCK_SIZE)
        elif PakCrypto._is_sm4_method(encryption_method):
            return Misc.align_up(n, SM4.block_length())
        else:
            return n
            
    @staticmethod
    def encrypt_block(plaintext, file: PurePath, encryption_method: int) -> bytes:
        if PakCrypto._is_simple1_method(encryption_method):
            return PakCrypto._encrypt_simple1(plaintext)
        elif PakCrypto._is_simple2_method(encryption_method):
            padded_plaintext = pad(plaintext, SIMPLE2_BLOCK_SIZE)
            return PakCrypto._encrypt_simple2(padded_plaintext)
        elif PakCrypto._is_sm4_method(encryption_method):
            return PakCrypto._encrypt_sm4(plaintext, file, encryption_method)
        else:
            assert False, f"Unknown encryption method: {encryption_method}"


    @staticmethod
    def decrypt_block(ciphertext, file: PurePath, encryption_method: int) -> bytes:
        if PakCrypto._is_simple1_method(encryption_method):
            return PakCrypto._decrypt_simple1(ciphertext)
        elif PakCrypto._is_simple2_method(encryption_method):
            return PakCrypto._decrypt_simple2(ciphertext)
        elif PakCrypto._is_sm4_method(encryption_method):
            return PakCrypto._decrypt_sm4(ciphertext, file, encryption_method)
        else:
            if encryption_method == 0:
                 return ciphertext
            assert False, f"Unknown encryption method: {encryption_method}"
            
    @staticmethod
    @lru_cache(maxsize=33)
    def generate_block_indices(n: int, encryption_method: int) -> list[int]:
        if not PakCrypto._is_sm4_method(encryption_method):
            return list(range(n))

        permutation = []
        lcg = PakCrypto._LCG(n)
        while len(permutation) != n:
            x = lcg.next() % n
            if x not in permutation:
                permutation.append(x)

        inverse = [0] * len(permutation)
        for i, x in enumerate(permutation):
            inverse[x] = i

        return inverse

    @staticmethod
    def stat():
        print(PakCrypto._derive_sm4_key.cache_info())
        print(PakCrypto._sm4_context_for_key.cache_info())

class PakCompression:
    @staticmethod
    @lru_cache(maxsize=33)
    def _zstd_decompressor(dict_data: bytes | None) -> ZstdDecompressor:
        dict_obj = ZstdCompressionDict(dict_data, DICT_TYPE_AUTO) if dict_data else None
        return ZstdDecompressor(dict_obj)

    @staticmethod
    @lru_cache(maxsize=128) 
    def _zstd_compressor(dict_data: bytes | None, level: int) -> ZstdCompressor:
        dict_obj = ZstdCompressionDict(dict_data, DICT_TYPE_AUTO) if dict_data else None
        return ZstdCompressor(level=level, dict_data=dict_obj)

    @staticmethod
    def decompress_block(block, dict_data: bytes | None, compression_method: int) -> bytes:
        if compression_method == CM_ZLIB:
            return zlib.decompress(block)
        elif compression_method == CM_ZSTD or compression_method == CM_ZSTD_DICT:
            if compression_method != CM_ZSTD_DICT:
                dict_data = None
            return PakCompression._zstd_decompressor(dict_data).decompress(block)
        else:
            assert False, f"Unknown decompression method: {compression_method}"

    @staticmethod
    def compress_block(block, dict_data: bytes | None, compression_method: int, level: int | None = None) -> bytes:
        if compression_method == CM_ZLIB:
            use_level = level if level is not None else 9
            return zlib.compress(block, level=use_level)
        elif compression_method == CM_ZSTD or compression_method == CM_ZSTD_DICT:
            use_level = level if level is not None else 22
            if compression_method != CM_ZSTD_DICT:
                dict_data = None
            return PakCompression._zstd_compressor(dict_data, use_level).compress(block)
        else:
            assert False, f"Unknown compression method: {compression_method}"

class CompressionFinder:
    ZLIB_LEVELS_TO_TRY = list(range(9, 0, -1))
    ZSTD_LEVELS_TO_TRY = list(range(22, 0, -1)) + list(range(-1, -8, -1))

    @staticmethod
    def find_best_level(
        uncompressed_chunk: bytes, 
        original_compressed_size: int, 
        dict_data: bytes | None, 
        compression_method: int
    ) -> (int | None, int):
        
        levels_to_try = []
        default_level = 9
        if compression_method == CM_ZLIB:
            levels_to_try = CompressionFinder.ZLIB_LEVELS_TO_TRY
            default_level = 9
        elif compression_method in [CM_ZSTD, CM_ZSTD_DICT]:
            levels_to_try = CompressionFinder.ZSTD_LEVELS_TO_TRY
            default_level = 22
        else:
            return None, len(uncompressed_chunk)

        best_fit_level = None
        closest_size_so_far = -1

        for level in levels_to_try:
            compressed_data = PakCompression.compress_block(uncompressed_chunk, dict_data, compression_method, level=level)
            current_size = len(compressed_data)

            if original_compressed_size >= current_size > closest_size_so_far:
                closest_size_so_far = current_size
                best_fit_level = level
                if current_size == original_compressed_size:
                    break
        
        if best_fit_level is not None:
            return best_fit_level, closest_size_so_far

        final_compressed = PakCompression.compress_block(uncompressed_chunk, dict_data, compression_method, level=default_level)
        return default_level, len(final_compressed)

class TencentPakFile:
    def __init__(self, file_path: PurePath, is_od=False):
        self._file_path = file_path
        with open(file_path, 'rb') as file:
            self._file_content = memoryview(file.read())
        self._is_od = is_od
        self._mount_point = PurePath()
        self._is_zstd_with_dict = 'zsdic' in str(self._file_path)
        self._zstd_dict = None
        self._files: list[TencentPakEntry] = []
        self._index: dict[PurePath, dict[str, TencentPakEntry]] = {}
        self._pak_info = TencentPakInfo(self._file_content, PakCrypto.zuc_keystream())

        self._verify_stem_hash()
        self._tencent_load_index()

    def _verify_stem_hash(self) -> None:
        if not self._is_od and self._pak_info.version >= 9:
            assert self._pak_info.stem_hash == zlib.crc32(self._file_path.stem.encode('utf-32le'))

    def _tencent_load_index(self) -> None:
        index_data = self._file_content[self._pak_info.index_offset:][:self._pak_info.index_size]

        if self._pak_info.index_encrypted:
            index_data = PakCrypto.decrypt_index(index_data, self._pak_info)
        else:
            index_data = bytes(index_data)

        self._verify_index_hash(index_data)
        self._load_index(index_data)

    def _verify_index_hash(self, index_data) -> None:
        expected_hash = self._pak_info.index_hash
        if not self._is_od and self._pak_info.version >= 8:
            assert expected_hash == PakCrypto.rsa_extract(self._pak_info.packed_index_hash, RSA_MOD_2)
        assert expected_hash == SHA1.new(index_data).digest()

    @staticmethod
    def _construct_mount_point(mount_point: str) -> PurePath:
        result = PurePath()
        for part in PurePath(mount_point).parts:
            if part != '..':
                result /= part
        return result

    def _peek_content(self, offset: int, size: int, encryption_method: int) -> memoryview:
        size = PakCrypto.align_encrypted_content_size(size, encryption_method)
        return self._file_content[offset:][:size]

    def _peek_block_content(self, block: PakCompressedBlock, encryption_method: int) -> memoryview:
        size = PakCrypto.align_encrypted_content_size(block.end - block.start, encryption_method)
        return self._file_content[block.start:][:size]

    def _construct_zstd_dict(self, dict_entry: TencentPakEntry) -> None:
        assert not self._zstd_dict
        assert not dict_entry.encrypted
        assert dict_entry.compression_method == CM_NONE

        reader = Reader(self._peek_content(dict_entry.offset, dict_entry.size, 0))

        dict_size = reader.u8()
        _ = reader.u4()
        assert dict_size == reader.u4()
        dict_data = reader.s(dict_size)
        self._zstd_dict = dict_data

    def _load_index(self, index_data) -> None:
        if self._pak_info.version <= 10:
            print("Warning: This pak version is very old and may not be fully supported.")

        reader = Reader(index_data)
        self._mount_point = self._construct_mount_point(reader.string())
        self._files = [TencentPakEntry(reader, self._pak_info.version) for _ in range(reader.u4())]

        try:
            num_dirs = reader.u8()
            for _ in range(num_dirs):
                dir_path = PurePath(reader.string())
                num_files_in_dir = reader.u8()
                e = {reader.string(): self._files[~reader.i4()] for _ in range(num_files_in_dir)}
                if self._is_zstd_with_dict and dir_path.name == 'zstddic':
                    assert len(e) == 1
                    self._construct_zstd_dict(e[[*e.keys()][0]])
                    continue
                self._index.update({PurePath(dir_path): e})
        except (struct.error, IndexError):
            print("Note: Directory reading ended, possibly due to outdated pak format.")
    
    def _get_method_str(self, method_int, is_encryption):
        if is_encryption:
            if PakCrypto._is_simple1_method(method_int): return "SIMPLE1"
            if PakCrypto._is_simple2_method(method_int): return "SIMPLE2"
            if PakCrypto._is_sm4_method(method_int): return f"SM4 (Type {method_int})"
            return "NONE" if method_int == 0 else "UNKNOWN"
        else:
            if method_int == CM_NONE: return "NONE"
            if method_int == CM_ZLIB: return "ZLIB"
            if method_int == CM_ZSTD: return "ZSTD"
            if method_int == CM_ZSTD_DICT: return "ZSTD_DICT"
            return "UNKNOWN"

    def _write_to_disk(self, file_path: Path, entry: TencentPakEntry) -> None:
        encryption_method = entry.encryption_method
        compression_method = entry.compression_method

        enc_str = self._get_method_str(encryption_method, True)
        comp_str = self._get_method_str(compression_method, False)
        print(f"-> Extracting file: {file_path.name} [{comp_str}/{enc_str}]")

        with open(file_path, 'wb') as file:
            if compression_method == CM_NONE:
                data = self._peek_content(entry.offset, entry.size, encryption_method)
                if entry.encrypted:
                    data = PakCrypto.decrypt_block(bytes(data), file_path, encryption_method)
                file.write(data)
                return

            decrypted_uncompressed_data = bytearray()
            for x in PakCrypto.generate_block_indices(len(entry.compressed_blocks), encryption_method):
                data = self._peek_block_content(entry.compressed_blocks[x], encryption_method)
                if entry.encrypted:
                    data = PakCrypto.decrypt_block(bytes(data), file_path, encryption_method)
                
                if not data:
                    continue
                
                decompressed_data = PakCompression.decompress_block(bytes(data), self._zstd_dict, compression_method)
                decrypted_uncompressed_data.extend(decompressed_data)
            
            file.write(decrypted_uncompressed_data[:entry.uncompressed_size])

    def _find_entry_by_name(self, file_name_to_find: str) -> Optional[Tuple[Path, TencentPakEntry]]:
        for dir_path, dir_content in self._index.items():
            for file_name, entry in dir_content.items():
                if file_name.lower() == file_name_to_find.lower():
                    full_path = self._mount_point / dir_path / file_name
                    return full_path, entry
        return None

    def dump_specific_file(self, out_path: Path, file_name_to_find: str) -> bool:
        found_item = self._find_entry_by_name(file_name_to_find)
        
        if not found_item:
            print(f"ERROR: File '{file_name_to_find}' not found in the pak archive.")
            return False

        full_path, entry = found_item
        
        target_path = out_path / self._mount_point / full_path.parent
        target_path.mkdir(parents=True, exist_ok=True)
        
        self._write_to_disk(target_path / file_name_to_find, entry)
        return True

    def repack(self, repack_dir: PurePath, target_pak_path: Path):
        print(f"\nSTARTING REPACK PROCESS: {target_pak_path.name}")
        
        repack_files_map = {p.name.lower(): p for p in Path(repack_dir).rglob('*') if p.is_file()}

        with open(target_pak_path, 'r+b') as target_file:
            for dir_path, dir_content in self._index.items():
                for file_name, entry in dir_content.items():
                    
                    if file_name.lower() not in repack_files_map:
                        continue
                    
                    modified_file_path = repack_files_map[file_name.lower()]

                    enc_str = self._get_method_str(entry.encryption_method, True)
                    comp_str = self._get_method_str(entry.compression_method, False)
                    print(f"\n-> REPACKING FILE: {file_name} [{comp_str}/{enc_str}]")

                    try:
                        with open(modified_file_path, 'rb') as f_modified:
                            modified_data = f_modified.read()

                        if entry.compression_method == CM_NONE:
                            data_to_write = modified_data
                            if entry.encrypted:
                                data_to_write = PakCrypto.encrypt_block(modified_data, modified_file_path, entry.encryption_method)
                            
                            if len(data_to_write) > entry.size:
                                print(f"    ERROR: File became too large after processing: {file_name}")
                                continue

                            target_file.seek(entry.offset)
                            target_file.write(data_to_write)
                            print(f"    SUCCESS: {file_name} repacked successfully")
                             
                        else:
                            block_indices = PakCrypto.generate_block_indices(len(entry.compressed_blocks), entry.encryption_method)
                            uncompressed_offset = 0
                            blocks_skipped = 0

                            for i, block_index in enumerate(block_indices):
                                block_info = entry.compressed_blocks[block_index]
                                chunk_size = entry.compression_block_size
                                
                                uncompressed_chunk = modified_data[uncompressed_offset : uncompressed_offset + chunk_size]
                                uncompressed_offset += chunk_size
                                
                                if not uncompressed_chunk:
                                    break
                                
                                compressed_chunk = b''
                                original_compressed_space = block_info.end - block_info.start
                                
                                if entry.compression_method == CM_ZLIB:
                                    compressed_chunk = PakCompression.compress_block(
                                        uncompressed_chunk, self._zstd_dict, entry.compression_method, level=9
                                    )
                                else:
                                    print(f"    -> Compressing block [{i}]", end="\r")
                                    best_level, _ = CompressionFinder.find_best_level(
                                        uncompressed_chunk, original_compressed_space, self._zstd_dict, entry.compression_method
                                    )
                                    compressed_chunk = PakCompression.compress_block(
                                        uncompressed_chunk, self._zstd_dict, entry.compression_method, level=best_level
                                    )
                                
                                data_to_write = compressed_chunk
                                if entry.encrypted:
                                    data_to_write = PakCrypto.encrypt_block(data_to_write, modified_file_path, entry.encryption_method)
                                
                                final_target_space = PakCrypto.align_encrypted_content_size(original_compressed_space, entry.encryption_method)
                                
                                if len(data_to_write) > final_target_space:
                                    print(f"    WARNING: Block [{i}] too large ({len(data_to_write)} > {final_target_space}), skipping")
                                    blocks_skipped += 1
                                    continue
                                
                                target_file.seek(block_info.start)
                                target_file.write(data_to_write)
                                if len(data_to_write) < final_target_space:
                                    padding = b'\x00' * (final_target_space - len(data_to_write))
                                    target_file.write(padding)
                            
                            if blocks_skipped > 0:                                
                                print(f"    PARTIAL SUCCESS: {file_name} (some blocks skipped)")
                            else:
                                print(f"    SUCCESS: {file_name} fully repacked")

                    except Exception as e:
                        print(f"    ERROR processing {file_name}: {e}")

# ====================== MAIN TOOL FUNCTIONS ======================

BASE_DIR = Path("/storage/emulated/0/Download/DAFAN")

def ensure_directories():
    (BASE_DIR / "PAK").mkdir(parents=True, exist_ok=True)
    (BASE_DIR / "UNPACK").mkdir(parents=True, exist_ok=True)
    (BASE_DIR / "REPACK").mkdir(parents=True, exist_ok=True)
    (BASE_DIR / "RESULT").mkdir(parents=True, exist_ok=True)

def unpack_pak(pak_file_path: str):
    try:
        pak_file = TencentPakFile(PurePath(pak_file_path))
        output_dir = BASE_DIR / "UNPACK" / Path(pak_file_path).stem
        
        print("\nPlease enter the name of the file you want to unpack (e.g., BP_PlayerPawn.uasset)")
        print("Or press Enter to cancel:", end=" ")
        specific_file_name = input().strip()

        if not specific_file_name:
            print("Unpack operation cancelled.")
            return

        print(f"\nSTARTING UNPACK: Searching for '{specific_file_name}' in {Path(pak_file_path).name}...")
        
        success = pak_file.dump_specific_file(output_dir, specific_file_name)
        
        if success:
            print(f"\nSUCCESS: Successfully extracted '{specific_file_name}' to {output_dir}")
        else:
            print(f"\nFAILED: Could not find or extract '{specific_file_name}'.")

    except Exception as e:
        import traceback
        print(f"ERROR during unpacking {pak_file_path}: {e}")
        traceback.print_exc()

def repack_pak(pak_file_path: str):
    try:
        repack_dir = BASE_DIR / "REPACK"
        result_dir = BASE_DIR / "RESULT"

        if not any(repack_dir.iterdir()):
            print(f"ERROR: REPACK folder at {repack_dir} is empty.")
            print("Please place your modified files in the REPACK folder.")
            return

        source_pak = Path(pak_file_path)
        target_pak = result_dir / source_pak.name
        
        print(f"\nCopying original pak to RESULT folder...")
        shutil.copy(source_pak, target_pak)
        print(f"Copy completed: {target_pak}")

        pak_file_meta = TencentPakFile(PurePath(source_pak))
        pak_file_meta.repack(repack_dir, target_pak)
        print(f"\nREPACK COMPLETED SUCCESSFULLY: {target_pak.name}")

    except Exception as e:
        import traceback
        print(f"ERROR during repacking {pak_file_path}: {e}")
        traceback.print_exc()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def banner():
    print("    PUBG MOBILE PAK TOOL")
    print("")
    print("")
    print()

def main():
    clear_screen()
    banner()
    ensure_directories()

    while True:
        menu_text = (
            "\n" + "="*15 + " DAFAN " + "="*15 + "\n"
            "1. UNPACK\n"
            "2. REPACK \n"
            "3. EXIT\n"
            + "="*42
        )
        print(menu_text)

        print("Enter your choice:", end=" ")
        choice = input().strip()

        if choice in ("1", "2"):
            action = "UNPACK" if choice == "1" else "REPACK"
            pak_dir = BASE_DIR / "PAK"
            
            if not pak_dir.exists():
                print(f"ERROR: PAK folder not found at {pak_dir}")
                continue

            pak_files = glob.glob(str(pak_dir / "*.pak"))

            if not pak_files:
                print("ERROR: No .pak files found in PAK folder!")
                continue

            print(f"\nSelect a .pak file to {action}:")
            for i, pak_file in enumerate(pak_files):
                print(f"{i+1}. {Path(pak_file).name}")

            while True:
                print(f"Enter file number (0 to return to menu):", end=" ")
                try:
                    file_num = int(input().strip())
                    if file_num == 0:
                        break
                    if 1 <= file_num <= len(pak_files):
                        selected_file = pak_files[file_num - 1]
                        if choice == "1":
                            unpack_pak(selected_file)
                        else:
                            repack_pak(selected_file)
                        input("\nPress Enter to continue...")
                        clear_screen()
                        banner()
                        break
                    else:
                        print("Invalid number. Please try again.")
                except ValueError:
                    print("Invalid input. Please enter a number.")

        elif choice == "3":
            print("Goodbye! Thank you for using the tool.")
            break
        else:
            print("Invalid choice. Please select 1, 2, or 3.")

if __name__ == '__main__':
    # Add a check for Python 3.8+ for it.batched
    if sys.version_info < (3, 8):
        def batched(iterable, n):
            "Batch data into tuples of length n. The last batch may be shorter."
            if n < 1:
                raise ValueError("n must be at least one")
            it = iter(iterable)
            while batch := tuple(it.islice(n)):
                yield batch
        it.batched = batched

    main()

