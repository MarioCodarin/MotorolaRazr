"""Hitagi read/write of the active 128 KiB PDS block. ERASE/BIN only for that block."""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools' / 'FlashTerminal'))
sys.path.insert(0, str(ROOT / 'research'))

import FlashTerminal as ft  # noqa: E402
from p2k_probe import VID, PID_P2K, wait_pid  # noqa: E402
from pds import PDS_SIZE
from scc_oracle import parse_read, p2k_to_flash, LOADER

PDS_ADDR = 0xA0040000
CHUNK = 0x0800
BIN_CHUNK = 32
PID_FLASH = 0x6403


def connect_loader():
    import usb.core
    if usb.core.find(idVendor=VID, idProduct=PID_FLASH) is None:
        p2k_to_flash()
    ft.set_logging_configuration(False)
    ft.timeout_read = 8000
    er, ew = ft.usb_init(ft.usb_devices, 'flash')
    if not er or not ew:
        raise SystemExit('no flash endpoints')
    boot = bytes(ft.mfp_cmd(er, ew, 'RQHW'))
    print('RQHW boot', boot)
    if b'FFFF' not in boot:
        print('uploading', LOADER)
        ft.mfp_upload_binary_to_addr(er, ew, str(LOADER), 0x80000000, 0x80000038, True)
        print('RQHW loader', bytes(ft.mfp_cmd(er, ew, 'RQHW')))
    print('RQSW', bytes(ft.mfp_cmd(er, ew, 'RQSW')))
    return er, ew


def read_mem(er, ew, addr: int, size: int) -> bytes:
    resp = bytes(ft.mfp_cmd(er, ew, 'READ', f'{addr:08X},{size:04X}'.encode()))
    data = parse_read(resp)
    if len(data) != size:
        raise IOError(f'READ {addr:08X},{size:04X} got {len(data)} raw={resp[:24]!r}')
    return data


def read_pds_block(er, ew) -> bytes:
    chunks = []
    addr = PDS_ADDR
    left = PDS_SIZE
    while left:
        n = min(left, CHUNK)
        chunks.append(read_mem(er, ew, addr, n))
        addr += n
        left -= n
    data = b''.join(chunks)
    if not data.startswith(b'PDS_'):
        raise IOError(f'bad PDS header {data[:16]!r}')
    return data


def write_pds_block(er, ew, data: bytes) -> None:
    if len(data) != PDS_SIZE:
        raise ValueError(f'PDS image {len(data)} != {PDS_SIZE}')
    if not data.startswith(b'PDS_'):
        raise ValueError('refusing to write non-PDS image')
    ft.timeout_write = 30000
    ft.timeout_read = 30000
    print('ERASE x2 (buffer mode)')
    print('E1', bytes(ft.mfp_cmd(er, ew, 'ERASE'))[:24])
    print('E2', bytes(ft.mfp_cmd(er, ew, 'ERASE'))[:24])
    print('ADDR', hex(PDS_ADDR), bytes(ft.mfp_addr(er, ew, PDS_ADDR))[:24])
    off = 0
    while off < PDS_SIZE:
        chunk = data[off:off + BIN_CHUNK]
        ack = bytes(ft.mfp_bin(er, ew, chunk))
        if off == 0 or (off & 0x1FFF) == 0:
            print(f'BIN {off:05X}+{len(chunk):04X}', ack[:20])
        if off == 0:
            time.sleep(8)
        off += len(chunk)


def restart(er, ew) -> None:
    try:
        ft.mfp_cmd(er, ew, 'RESTART')
    except Exception as exc:
        print('restart', exc)
    for i in range(30):
        import usb.core
        dev = usb.core.find(idVendor=VID)
        print('usb', i, hex(dev.idProduct) if dev else None)
        if dev is not None and dev.idProduct == 0x6402:
            return
        time.sleep(1)
    raise SystemExit('phone did not return to 6402')
