"""Read ArgonLV unique-id registers via Hitagi. Read-only: no ERASE/BIN to NOR."""

from __future__ import annotations

import glob
import sys
import time
from pathlib import Path

import serial
import usb.core
import usb.util

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools' / 'FlashTerminal'))
sys.path.insert(0, str(ROOT / 'research'))

import FlashTerminal as ft  # noqa: E402
from p2k_probe import P2K05, VID, PID_AT, PID_P2K, wait_pid, switch_p2k  # noqa: E402

PID_FLASH = 0x6403
LOADER = ROOT / 'tools' / 'Hitagi' / 'hitagi.bin'


def p2k_to_flash() -> None:
    dev = usb.core.find(idVendor=VID, idProduct=PID_P2K)
    if dev is None:
        raise SystemExit('P2K device missing')
    p2k = P2K05(dev)
    raw = p2k.cmd(0x0D, b'')
    print('flash cmd', raw.hex())
    time.sleep(8)
    flash = wait_pid(PID_FLASH, 15)
    if flash is None:
        raise SystemExit('flash 6403 did not appear')
    print('flash up')


def parse_read(resp: bytes) -> bytes:
    data = resp[6:]
    data = data[2:]
    data = data[:-2]
    return bytes(data)


def main() -> None:
    ft.set_logging_configuration(True)
    ft.timeout_read = 8000
    out = Path('diagnostics')
    switch_p2k()
    p2k_to_flash()
    er, ew = ft.usb_init(ft.usb_devices, 'flash')
    if not er or not ew:
        raise SystemExit('no flash endpoints')
    print('RQHW boot', ft.mfp_cmd(er, ew, 'RQHW'))
    print('uploading', LOADER)
    ft.mfp_upload_binary_to_addr(er, ew, str(LOADER), 0x80000000, 0x80000038, True)
    print('RQHW loader', ft.mfp_cmd(er, ew, 'RQHW'))
    rqsn = ft.mfp_cmd(er, ew, 'RQSN')
    print('RQSN', rqsn)
    (out / 'rqsn.bin').write_bytes(bytes(rqsn))
    for addr, size, name in (
        (0x5001D004, 0x1C, 'uid_5001D004'),
        (0x43F08020, 0x18, 'iim_43F08020'),
    ):
        try:
            resp = ft.mfp_cmd(er, ew, 'READ', f'{addr:08X},{size:04X}'.encode())
        except Exception as exc:
            print(name, 'ERR', exc)
            continue
        body = parse_read(bytes(resp))
        path = out / f'{name}.bin'
        path.write_bytes(body)
        print(name, body.hex(), 'raw', bytes(resp)[:48])
    print('RESTART')
    try:
        ft.mfp_cmd(er, ew, 'RESTART')
    except Exception as exc:
        print('restart', exc)


if __name__ == '__main__':
    main()
