"""Recover the V3xx SEEM Blowfish key from dump bytes and IIM unique id."""

from __future__ import annotations

from pathlib import Path

from pds import parse_pds, latest_payload, PDS_SIZE, ACTIVE_STATUSES
from seem_crypt import (
    unique_id_key, session_key, scramble, decrypt_record, tdes_cbc,
    split_iv_ct, UID_ASCII_LEN, scc_decrypt_record,
)


def _structured(seem: int, plain: bytes, p2k: bytes) -> bool:
    if p2k and len(p2k) >= 8 and (plain == p2k or plain[:len(p2k)] == p2k):
        return True
    if len(plain) >= 2 and plain[:2] == seem.to_bytes(2, 'big'):
        return True
    return False


def _imei(dump_dir: Path) -> bytes:
    path = dump_dir / 'IMEI.txt'
    if path.is_file():
        return path.read_text().strip().encode('ascii')
    return b''


def _uid_blobs(iim: bytes) -> list[bytes]:
    if len(iim) >= 28:
        words = [int.from_bytes(iim[i:i + 4], 'big') for i in range(0, 28, 4)]
        low_fwd = bytes(w & 0xFF for w in words)
        low_rev = bytes(w & 0xFF for w in reversed(words))
        return [iim[:28], iim[:16], iim[:18], iim[:24], low_fwd, low_rev]
    return [iim] if iim else []


def candidate_keys(image: bytes, dump_dir: Path, iim: bytes = b'') -> list[bytes]:
    keys: list[bytes] = []
    seen: set[bytes] = set()
    if not iim:
        path = dump_dir / 'iim_uid.bin'
        if path.is_file():
            iim = path.read_bytes()
    uids = _uid_blobs(iim)

    def add(key: bytes) -> None:
        if 4 <= len(key) <= 56 and key not in seen:
            seen.add(key)
            keys.append(key)

    for uid in uids:
        add(unique_id_key(uid))
        add(scramble(uid.hex().encode('ascii')[:UID_ASCII_LEN].ljust(UID_ASCII_LEN, b'\0')))
        if 4 <= len(uid) <= 56:
            add(uid)
        add((uid * 8)[:24])
        add(uid.ljust(24, b'\0')[:24])
        add(uid.ljust(16, b'\0')[:16] + uid.ljust(8, b'\0')[:8])
        for pref in _prefixes(image, dump_dir):
            try:
                add(session_key(pref, uid))
            except ValueError:
                continue
    return keys


def _prefixes(image: bytes, dump_dir: Path) -> list[bytes]:
    out: list[bytes] = []
    imei = _imei(dump_dir)
    if imei:
        out.append(imei)
        packed = imei.decode()
        if len(packed) % 2:
            packed += 'F'
        out.append(bytes.fromhex(packed))
    for name in ('0004_0001.seem', '0026_0001.seem', '0003_0001.seem'):
        p = dump_dir / name
        if p.is_file():
            data = p.read_bytes()
            if data:
                out.append(data)
    area = parse_pds(image[0x40000:0x40000 + PDS_SIZE])
    for record in area.records:
        if record.status in ACTIVE_STATUSES and 4 <= len(record.payload) <= 20:
            out.append(record.payload)
    ident = latest_payload(area, 0x02CB)
    if ident:
        out.append(ident[:16])
    return out


def recover_key(image: bytes, dump_dir: Path, iim: bytes = b'') -> bytes | None:
    area = parse_pds(image[0x40000:0x40000 + PDS_SIZE])
    blob = latest_payload(area, 0x01C3)
    p2k_path = dump_dir / '01c3_0001.seem'
    p2k = p2k_path.read_bytes() if p2k_path.is_file() else b''
    if not blob or len(blob) < 16:
        return None
    iv, ct = split_iv_ct(blob)
    for key in candidate_keys(image, dump_dir, iim):
        plains = []
        if len(key) in (16, 24):
            try:
                plains.append(scc_decrypt_record(key, blob, logical=32))
            except ValueError:
                pass
        try:
            plains.append(decrypt_record(key, blob))
        except ValueError:
            pass
        if len(key) in (16, 24):
            try:
                plains.append(tdes_cbc(key, ct, encrypt=False, iv=iv))
                plains.append(tdes_cbc(key, blob, encrypt=False, iv=b'\0' * 8))
            except ValueError:
                pass
        for plain in plains:
            if _structured(0x01C3, plain, p2k):
                return key
    return None
