"""Unlock: 015C lock-byte cleared (keep body), 01C3 08-fields cleared (keep FF tail).

All-zero 01C3 boot-looped. All-zero 015C booted but stayed locked.
015F decrypt of 015C proved the cipher is shared (flags 0x87 vs 0xAF).
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'research'))
sys.path.insert(0, str(ROOT / 'tools' / 'FlashTerminal'))

import usb.core  # noqa: E402
import usb.util  # noqa: E402
from pds import parse_pds, latest_payload, replace_latest_payload, PDS_SIZE  # noqa: E402
from p2k_probe import VID, read_seem, wait_pid  # noqa: E402
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
PT_015C = (DIAG / '015c_via_015f.seem').read_bytes()
UNLOCK_015C = b'\x00' + PT_015C[1:]
UNLOCK_01C3 = b'\x00' * 13 + b'\xff' * 19
SEEM_03FF_LOGICAL = 620


def to_flash(p2k) -> None:
    print('flash cmd', p2k.cmd(0x0D, b'').hex(), flush=True)
    usb.util.dispose_resources(p2k.dev)
    if wait_pid(PID_FLASH, 15) is None:
        raise SystemExit('no 6403')


def main() -> None:
    require_pds_write()
    if len(PT_015C) != 20:
        raise SystemExit('need 015c_via_015f.seem')
    print('015C orig', PT_015C.hex(), flush=True)
    print('015C unlk', UNLOCK_015C.hex(), flush=True)
    print('01C3 unlk', UNLOCK_01C3.hex(), flush=True)
    wrap = scc_wrap(UNLOCK_01C3)
    print('01C3 wrap', wrap.hex(), flush=True)

    p2k = open_p2k()
    wr = write_seem(p2k, 0x015F, UNLOCK_015C)
    got = p2k_payload(read_seem(p2k, 0x015F))
    print('015F write', wr[:16].hex(), 'got', got.hex(), flush=True)
    if got != UNLOCK_015C:
        raise SystemExit('015F identity fail')
    to_flash(p2k)

    er, ew = connect_loader()
    live = read_pds_block(er, ew)
    (SCRATCH / 'pds_live_unlock_cleared.bin').write_bytes(live)
    (DIAG / 'pds_live_unlock_cleared.bin').write_bytes(live)
    area = parse_pds(live)
    ct15 = latest_payload(area, 0x015F)
    if ct15 is None or len(ct15) != 32:
        raise SystemExit('015F CT')
    print('015F CT', ct15.hex(), flush=True)

    orig_area = parse_pds(ORIG)
    patched = live
    patched = replace_latest_payload(patched, 0x015C, ct15)
    patched = replace_latest_payload(patched, 0x015D, ct15)
    patched = replace_latest_payload(patched, 0x015F, latest_payload(orig_area, 0x015F))
    # 01C3 left original: all-zero 01C3 reboot-looped.
    if not parse_pds(patched).checksum_valid:
        raise SystemExit('checksum')
    (DIAG / 'pds_unlock_cleared.bin').write_bytes(patched)
    (SCRATCH / 'pds_unlock_cleared.bin').write_bytes(patched)
    print('writing unlock image', flush=True)
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
    print('015C', read_seem(p2k, 0x015C).hex(), flush=True)
    print('restart', p2k.cmd(0x22, b'').hex(), flush=True)
    usb.util.dispose_resources(p2k.dev)
    wait_at()
    print('done', flush=True)


if __name__ == '__main__':
    main()
