"""Decrypt ACL 015C by copying its stored blob onto writable 015F.

015F is 20-byte encrypted (flags 0x87), not in the P2K ACL table.
01C3 is not modified. Original PDS backup remains the restore image.
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
from p2k_probe import VID, read_seem  # noqa: E402
from os_oracle import p2k_payload, open_p2k, wait_at, write_seem  # noqa: E402
from hitagi_pds import connect_loader, read_pds_block, write_pds_block, restart, PID_FLASH  # noqa: E402
from p2k_probe import wait_pid  # noqa: E402
from pds_write_guard import require_pds_write  # noqa: E402

SCRATCH = Path('/var/folders/w9/xz8w2l7s4c30fdp61p0bnxph0000gn/T/grok-goal-69e2a524b376/implementer')
DIAG = ROOT / 'diagnostics'
BACKUP = DIAG / 'nor_a000.bin'


def main() -> None:
    require_pds_write()
    orig = BACKUP.read_bytes()[0x40000:0x40000 + PDS_SIZE]
    area = parse_pds(orig)
    ct15c = latest_payload(area, 0x015C)
    ct15f = latest_payload(area, 0x015F)
    if ct15c is None or ct15f is None or len(ct15c) != 32 or len(ct15f) != 32:
        raise SystemExit('015C/015F stored size')
    if ct15c == ct15f:
        raise SystemExit('015C already equals 015F')
    patched = replace_latest_payload(orig, 0x015F, ct15c)
    if not parse_pds(patched).checksum_valid:
        raise SystemExit('checksum')
    if latest_payload(parse_pds(patched), 0x01C3) != latest_payload(area, 0x01C3):
        raise SystemExit('01C3 changed')
    (DIAG / 'pds_015f_is_015c.bin').write_bytes(patched)
    (SCRATCH / 'pds_015f_is_015c.bin').write_bytes(patched)
    print('015C CT', ct15c.hex())
    print('image ready', len(patched), flush=True)

    p2k = open_p2k()
    print('flash cmd', p2k.cmd(0x0D, b'').hex(), flush=True)
    usb.util.dispose_resources(p2k.dev)
    if wait_pid(PID_FLASH, 15) is None:
        raise SystemExit('flash 6403 did not appear')
    er, ew = connect_loader()
    live = read_pds_block(er, ew)
    (SCRATCH / 'pds_before_015f_oracle.bin').write_bytes(live)
    print('live 015C', latest_payload(parse_pds(live), 0x015C).hex()[:32], flush=True)
    write_pds_block(er, ew, patched)
    verify = read_pds_block(er, ew)
    print('verify', verify == patched, flush=True)
    if verify != patched:
        write_pds_block(er, ew, orig)
        restart(er, ew)
        raise SystemExit('verify fail, original restored')
    restart(er, ew)
    wait_at()
    time.sleep(2)
    p2k = open_p2k()
    pt = p2k_payload(read_seem(p2k, 0x015F))
    print('015F as 015C PT', len(pt), pt.hex(), flush=True)
    (DIAG / '015c_via_015f.seem').write_bytes(pt)
    (SCRATCH / '015c_via_015f.seem').write_bytes(pt)
    wr = write_seem(p2k, 0x015F, b'\xff' * 20)
    got = p2k_payload(read_seem(p2k, 0x015F))
    print('restore 015F FF', wr[:16].hex(), got.hex(), flush=True)
    print('01C3', p2k_payload(read_seem(p2k, 0x01C3)).hex(), flush=True)
    print('restart', p2k.cmd(0x22, b'').hex(), flush=True)
    usb.util.dispose_resources(p2k.dev)
    wait_at()
    print('done', flush=True)


if __name__ == '__main__':
    main()
