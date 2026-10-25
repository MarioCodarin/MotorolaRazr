"""01C3 surgical: clear the two 0x08 lock fields, keep the 19-byte FF tail.

All-zero 01C3 (no FF tail) reboot-looped. 015C lock-byte clear booted, still locked.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'research'))
sys.path.insert(0, str(ROOT / 'tools' / 'FlashTerminal'))

import usb.util  # noqa: E402
from pds import parse_pds, latest_payload, replace_latest_payload, PDS_SIZE  # noqa: E402
from p2k_probe import read_seem, wait_pid  # noqa: E402
from os_oracle import p2k_payload, open_p2k, wait_at, write_seem  # noqa: E402
from hitagi_pds import (  # noqa: E402
    connect_loader, read_pds_block, write_pds_block, restart, PID_FLASH,
)
from seem_crypt import scc_wrap  # noqa: E402
from pds_write_guard import require_pds_write  # noqa: E402

if __name__ == '__main__':
    require_pds_write()

SCRATCH = Path('/var/folders/w9/xz8w2l7s4c30fdp61p0bnxph0000gn/T/grok-goal-69e2a524b376/implementer')
DIAG = ROOT / 'diagnostics'
ORIG = (DIAG / 'nor_a000.bin').read_bytes()[0x40000:0x40000 + PDS_SIZE]
UNLOCK_01C3 = b'\x00' * 13 + b'\xff' * 19
SEEM_03FF_LOGICAL = 620


def main() -> None:
    require_pds_write()
    wrap = scc_wrap(UNLOCK_01C3)
    print('PT', UNLOCK_01C3.hex(), flush=True)
    print('wrap', wrap.hex(), flush=True)
    p2k = open_p2k()
    pt = wrap + b'\xff' * (SEEM_03FF_LOGICAL - 40)
    wr = write_seem(p2k, 0x03FF, pt)
    got = p2k_payload(read_seem(p2k, 0x03FF))
    print('03FF', wr[:16].hex(), got[:40].hex(), flush=True)
    if got[:40] != pt[:40]:
        raise SystemExit('03FF identity fail')
    print('flash cmd', p2k.cmd(0x0D, b'').hex(), flush=True)
    usb.util.dispose_resources(p2k.dev)
    if wait_pid(PID_FLASH, 15) is None:
        raise SystemExit('no 6403')
    er, ew = connect_loader()
    live = read_pds_block(er, ew)
    (DIAG / 'pds_live_01c3_tail.bin').write_bytes(live)
    ct = latest_payload(parse_pds(live), 0x03FF)
    head = ct[:40]
    print('CT40', head.hex(), flush=True)
    orig_area = parse_pds(ORIG)
    patched = live
    patched = replace_latest_payload(patched, 0x01C3, head)
    patched = replace_latest_payload(patched, 0x01C4, head)
    patched = replace_latest_payload(patched, 0x03FF, latest_payload(orig_area, 0x03FF))
    if not parse_pds(patched).checksum_valid:
        raise SystemExit('checksum')
    (DIAG / 'pds_01c3_tail.bin').write_bytes(patched)
    write_pds_block(er, ew, patched)
    verify = read_pds_block(er, ew)
    print('verify', verify == patched, flush=True)
    if verify != patched:
        write_pds_block(er, ew, ORIG)
        restart(er, ew)
        raise SystemExit('verify fail, original restored')
    restart(er, ew)
    wait_at()
    time.sleep(2)
    p2k = open_p2k()
    print('01C3', p2k_payload(read_seem(p2k, 0x01C3)).hex(), flush=True)
    print('01C4', p2k_payload(read_seem(p2k, 0x01C4)).hex(), flush=True)
    print('restart', p2k.cmd(0x22, b'').hex(), flush=True)
    usb.util.dispose_resources(p2k.dev)
    wait_at()
    print('done', flush=True)


if __name__ == '__main__':
    main()
