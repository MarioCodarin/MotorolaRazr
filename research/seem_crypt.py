"""SEEM record transform used by this V3xx firmware.

Subsidy SEEMs are encrypted by the ArgonLV SCC (Freescale SCM) as
3DES-CBC. Alg0/1 at A07B83FE/A07B8540 copy words to 0x53FAC500/900,
issue CTRL 6 (enc) or 7 (dec), and run CRC32 (A07B8300, poly 0x04C11DB7)
over the SCC RAM as an integrity word. The fused SCC secret is not in
the NOR dump. A08130AC/A081B3DE Blowfish-CBC is the TLS path.
A07B5A2A: stored size is pad8(logical)+8 when 8-aligned (IV prepend).
"""

from __future__ import annotations

from Crypto.Cipher import Blowfish, DES3


SCRAMBLE_ROUNDS = 3
UID_ASCII_LEN = 0x24


def scramble(data: bytes, rounds: int = SCRAMBLE_ROUNDS) -> bytes:
    buf = bytearray(data)
    n = len(buf)
    if n == 0:
        return bytes(buf)
    for _ in range(rounds):
        for i in range(n):
            idx = (i + 1) % n
            idx2 = (idx + buf[idx]) % n
            buf[i], buf[idx2] = buf[idx2], buf[i]
    return bytes(buf)


def uid_hex36(uid: bytes) -> bytes:
    hex_ascii = uid.hex().encode('ascii').lower()
    if len(hex_ascii) < UID_ASCII_LEN:
        hex_ascii = hex_ascii + b'\0' * (UID_ASCII_LEN - len(hex_ascii))
    return hex_ascii[:UID_ASCII_LEN]


def session_key(prefix: bytes, uid: bytes) -> bytes:
    """A08130AC: prefix length must be > 0; total key is 4-56 bytes."""
    if not prefix:
        raise ValueError('A08130AC rejects a zero-length prefix')
    raw = prefix + uid_hex36(uid)
    if len(raw) > 56:
        raw = raw[:56]
    if len(raw) < 4:
        raise ValueError('Blowfish key length 4-56')
    return scramble(raw)


def unique_id_key(uid: bytes) -> bytes:
    """UID-only scramble (36-byte hex). Firmware also requires a prefix."""
    return scramble(uid_hex36(uid))


def bf_ecb(key: bytes, data: bytes, encrypt: bool) -> bytes:
    if len(data) % 8:
        raise ValueError('Blowfish length must be a multiple of 8')
    if not (4 <= len(key) <= 56):
        raise ValueError('Blowfish key length 4-56')
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    return cipher.encrypt(data) if encrypt else cipher.decrypt(data)


CRC32_POLY = 0x04C11DB7
CRC32_INIT = 0xFFFFFFFF


def crc32_table() -> list[int]:
    table = []
    for i in range(256):
        crc = i << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ CRC32_POLY) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
        table.append(crc)
    return table


_CRC32_TABLE = crc32_table()


def crc32_words(data: bytes, init: int = CRC32_INIT) -> int:
    """A07B8300: MSB-first CRC32 over big-endian 32-bit words."""
    if len(data) % 4:
        raise ValueError('CRC length must be a multiple of 4')
    crc = init & 0xFFFFFFFF
    for i in range(0, len(data), 4):
        word = data[i:i + 4]
        for byte in word:
            idx = ((crc >> 24) ^ byte) & 0xFF
            crc = ((crc << 8) & 0xFFFFFFFF) ^ _CRC32_TABLE[idx]
    return crc


def tdes_cbc(key: bytes, data: bytes, encrypt: bool, iv: bytes = b'\0' * 8) -> bytes:
    if len(data) % 8:
        raise ValueError('3DES length must be a multiple of 8')
    if len(key) not in (16, 24):
        raise ValueError('3DES key length 16 or 24')
    if len(iv) != 8:
        raise ValueError('IV must be 8 bytes')
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    return cipher.encrypt(data) if encrypt else cipher.decrypt(data)


def bf_cbc(key: bytes, data: bytes, encrypt: bool, iv: bytes = b'\0' * 8) -> bytes:
    if len(data) % 8:
        raise ValueError('Blowfish length must be a multiple of 8')
    if not (4 <= len(key) <= 56):
        raise ValueError('Blowfish key length 4-56')
    if len(iv) != 8:
        raise ValueError('IV must be 8 bytes')
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
    return cipher.encrypt(data) if encrypt else cipher.decrypt(data)


def split_iv_ct(blob: bytes) -> tuple[bytes, bytes]:
    if len(blob) < 16 or len(blob) % 8:
        raise ValueError('PDS blob must be IV||CT, 8-byte aligned')
    return blob[:8], blob[8:]


def decrypt_record(key: bytes, blob: bytes) -> bytes:
    iv, ct = split_iv_ct(blob)
    if len(key) in (16, 24):
        return tdes_cbc(key, ct, encrypt=False, iv=iv)
    return bf_cbc(key, ct, encrypt=False, iv=iv)


def encrypt_record(key: bytes, plain: bytes, iv: bytes) -> bytes:
    if len(plain) % 8:
        raise ValueError('plaintext must be 8-byte aligned')
    if len(key) in (16, 24):
        return iv + tdes_cbc(key, plain, encrypt=True, iv=iv)
    return iv + bf_cbc(key, plain, encrypt=True, iv=iv)


def roundtrip(key: bytes, blob: bytes) -> bool:
    iv, ct = split_iv_ct(blob)
    plain = decrypt_record(key, blob)
    return encrypt_record(key, plain, iv) == blob


# ArgonLV SCC SEEM payload: 8-pad the logical plaintext, append
# 0xB17219E9 (A07B86DC), append CRC32 of those words (A07B8300),
# then 3DES-CBC with IV=0 (alg0 zeros scc+0x20/0x24). Stored size is
# pad8(logical)+8. Type-0x40 RED/BLACK start 0x20.
SCC_MAGIC = bytes.fromhex('B17219E9')
SCC_IV = b'\x00' * 8


def scc_logical_size(stored: int) -> int:
    """Invert A07B5A2A: stored = pad8(logical)+8."""
    inner = stored - 8
    if inner <= 0 or inner % 8:
        raise ValueError('stored size is not pad8(logical)+8')
    return inner


def scc_wrap(plain: bytes) -> bytes:
    """Build the SCC cipher input for a logical SEEM payload."""
    pad = (8 - (len(plain) % 8)) % 8
    body = plain + b'\x00' * pad + SCC_MAGIC
    crc = crc32_words(body)
    return body + crc.to_bytes(4, 'big')


def scc_unwrap(wrapped: bytes, logical: int) -> bytes:
    if logical < 0 or logical > len(wrapped) - 8:
        raise ValueError('logical length does not fit SCC wrap')
    body, crc_b = wrapped[:-4], wrapped[-4:]
    if crc32_words(body).to_bytes(4, 'big') != crc_b:
        raise ValueError('SCC CRC32 mismatch')
    if body[-4:] != SCC_MAGIC:
        raise ValueError('SCC magic mismatch')
    padded = body[:-4]
    if padded[logical:] != b'\x00' * (len(padded) - logical):
        raise ValueError('SCC pad mismatch')
    return padded[:logical]


def scc_encrypt_record(key: bytes, plain: bytes) -> bytes:
    wrapped = scc_wrap(plain)
    if len(key) in (16, 24):
        return tdes_cbc(key, wrapped, encrypt=True, iv=SCC_IV)
    return bf_cbc(key, wrapped, encrypt=True, iv=SCC_IV)


def scc_decrypt_record(key: bytes, blob: bytes, logical: int | None = None) -> bytes:
    if logical is None:
        logical = scc_logical_size(len(blob))
        # 20-byte subsidy SEEMs store 32 bytes (pad8(20)+8); 8-aligned
        # 24-byte inner would also be 32. Prefer the attr-table 20.
        if len(blob) == 32:
            logical = 20
        elif len(blob) == 40:
            logical = 32
    if len(key) in (16, 24):
        wrapped = tdes_cbc(key, blob, encrypt=False, iv=SCC_IV)
    else:
        wrapped = bf_cbc(key, blob, encrypt=False, iv=SCC_IV)
    return scc_unwrap(wrapped, logical)


def scc_roundtrip(key: bytes, blob: bytes, logical: int | None = None) -> bool:
    plain = scc_decrypt_record(key, blob, logical)
    return scc_encrypt_record(key, plain) == blob
