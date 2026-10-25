"""Restore the original active PDS block from nor_a000.bin.

Waits for USB 22b8:6403 (bootloader) or 6402/6401, then writes the 128 KiB
backup at A0040000. Does not touch A0060000.
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

SCRATCH = Path('/var/folders/w9/xz8w2l7s4c30fdp61p0bnxph0000gn/T/grok-goal-69e2a524b376/implementer')
BACKUP = ROOT / 'diagnostics' / 'nor_a000.bin'


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
    if PID_AT in pids:
        import serial, glob
        ports = sorted(glob.glob('/dev/cu.usbmodem*'))
        if not ports:
            time.sleep(0.4)
            ports = sorted(glob.glob('/dev/cu.usbmodem*'))
        if ports:
            ser = serial.Serial(ports[0], 115200, timeout=0.4)
            ser.write(b'AT+MODE=24\r')
            ser.close()
            print('AT+MODE=24', ports[0], flush=True)
        if wait_pid(PID_FLASH, 8) is None:
            raise SystemExit('6403 did not appear after AT+MODE=24')
        return
    if PID_P2K in pids:
        from p2k_probe import P2K05
        p2k = P2K05(usb.core.find(idVendor=VID, idProduct=PID_P2K))
        print('P2K 0x0D', p2k.cmd(0x0D, b'').hex(), flush=True)
        import usb.util
        usb.util.dispose_resources(p2k.dev)
        if wait_pid(PID_FLASH, 12) is None:
            raise SystemExit('6403 did not appear after P2K 0x0D')
        return
    raise SystemExit('no Motorola USB')


def main() -> None:
    backup = original_pds()
    (SCRATCH / 'pds_restore_source.bin').write_bytes(backup)
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
        (SCRATCH / 'pds_before_restore.bin').write_bytes(live)
        (ROOT / 'diagnostics' / 'pds_before_restore.bin').write_bytes(live)
        print('saved live PDS', len(live), live[:10].hex(), flush=True)
    print('writing original PDS', PDS_ADDR, len(backup), flush=True)
    write_pds_block(er, ew, backup)
    verify = read_pds_block(er, ew)
    (SCRATCH / 'pds_after_restore.bin').write_bytes(verify)
    ok = verify == backup
    print('verify match', ok, flush=True)
    if not ok:
        raise SystemExit('RESTORE VERIFY FAILED')
    restart(er, ew)
    print('restore complete', flush=True)


if __name__ == '__main__':
    main()
