"""Restore the original active PDS block from nor_a000.bin.

Waits until USB shows 22b8:6403, then writes the 128 KiB backup at
A0040000. Does not send AT+MODE=24. Does not touch A0060000.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'research'))
sys.path.insert(0, str(ROOT / 'tools' / 'FlashTerminal'))

import usb.core  # noqa: E402
from pds import parse_pds, PDS_SIZE  # noqa: E402
from hitagi_pds import (  # noqa: E402
    connect_loader, read_pds_block, write_pds_block, restart,
    PDS_ADDR, PID_FLASH,
)
from p2k_probe import VID, PID_P2K, PID_AT, wait_pid  # noqa: E402

DIAG = ROOT / 'diagnostics'
BACKUP = DIAG / 'nor_a000.bin'


def original_pds() -> bytes:
    data = BACKUP.read_bytes()[0x40000:0x40000 + PDS_SIZE]
    area = parse_pds(data)
    if not area.checksum_valid:
        raise SystemExit('original PDS checksum invalid')
    return data


def mot_pids() -> list[int]:
    return [d.idProduct for d in usb.core.find(find_all=True, idVendor=VID) or []]


def hold_flash() -> None:
    pids = mot_pids()
    print('pids', [hex(p) for p in pids], flush=True)
    if PID_FLASH in pids:
        return
    print(
        'Hold the bootloader keys until USB shows 22b8:6403. '
        'AT+MODE=24 is not sent.',
        flush=True,
    )
    if wait_pid(PID_FLASH, 180) is None:
        raise SystemExit('6403 did not appear. No AT+MODE=24 was sent.')


def main() -> None:
    backup = original_pds()
    DIAG.mkdir(exist_ok=True)
    (DIAG / 'pds_restore_source.bin').write_bytes(backup)
    print('waiting for 22b8:6403/6402/6401 to restore A0040000', flush=True)
    deadline = time.time() + 600
    last = None
    while time.time() < deadline:
        pids = tuple(sorted(mot_pids()))
        if pids != last:
            print('usb', [hex(p) for p in pids], flush=True)
            last = pids
        if PID_FLASH in pids or PID_AT in pids or PID_P2K in pids:
            break
        time.sleep(0.05)
    else:
        raise SystemExit('timeout: phone never enumerated')

    hold_flash()
    er, ew = connect_loader()
    try:
        live = read_pds_block(er, ew)
    except Exception as exc:
        print('live read failed', exc, flush=True)
        live = b''
    if live:
        (DIAG / 'pds_before_restore.bin').write_bytes(live)
        print('saved live PDS', len(live), live[:10].hex(), flush=True)
    print('writing original PDS', PDS_ADDR, len(backup), flush=True)
    write_pds_block(er, ew, backup)
    verify = read_pds_block(er, ew)
    (DIAG / 'pds_after_restore.bin').write_bytes(verify)
    ok = verify == backup
    print('verify match', ok, flush=True)
    if not ok:
        raise SystemExit('RESTORE VERIFY FAILED')
    restart(er, ew)
    print('restore complete', flush=True)


if __name__ == '__main__':
    main()
