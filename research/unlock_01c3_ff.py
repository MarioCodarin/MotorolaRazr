"""01C3/01C4 surgical attempt #3: flip the two lock bytes to 0xFF.

Prior attempts (see README / git history) set these two bytes (offsets 3
and 4 of the 32-byte plaintext: 00 00 00 08 | 08 00 00 00 ...) to 0x00,
either alone (015C/015D oracle) or together with the whole leading word
(01C3/01C4 tail-preserving patch). Both booted but the phone stayed
locked. This firmware's own record convention treats 0xFF as the
"unset/disabled" sentinel (19 trailing 0xFF bytes = unused lock slots),
so 0x00 may actually mean "defined/zeroed" rather than "off". This
attempt sets indices 3 and 4 to 0xFF instead, leaving every other byte
identical to the verified original.

Full automatic rollback to the known-good backup on any verify failure
or failure to re-enumerate as 22b8:6402 after restart.
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
from p2k_probe import read_seem, wait_pid, VID  # noqa: E402
from os_oracle import p2k_payload, open_p2k, write_seem  # noqa: E402
from hitagi_pds import (  # noqa: E402
    connect_loader, read_pds_block, write_pds_block, restart, PID_FLASH,
)
from seem_crypt import scc_wrap  # noqa: E402
from restore_pds_backup import mot_pids, hold_flash  # noqa: E402
from pds_write_guard import require_pds_write  # noqa: E402

if __name__ == '__main__':
    require_pds_write()

DIAG = ROOT / 'diagnostics'
ORIG_BLOCK = (DIAG / 'nor_a000.bin').read_bytes()[0x40000:0x40000 + PDS_SIZE]
SEEM_03FF_LOGICAL = 620


def wait_at(seconds: float = 60.0) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        import usb.core
        dev = usb.core.find(idVendor=VID)
        if dev is not None and dev.idProduct == 0x6402:
            return True
        time.sleep(1)
    return False


def restore_and_bail(er, ew, reason: str) -> None:
    print('ROLLING BACK:', reason, flush=True)
    write_pds_block(er, ew, ORIG_BLOCK)
    verify = read_pds_block(er, ew)
    print('rollback verify match', verify == ORIG_BLOCK, flush=True)
    restart(er, ew)
    if not wait_at(90):
        raise SystemExit('CRITICAL: phone did not return to AT mode after rollback restart')
    raise SystemExit(f'aborted and rolled back: {reason}')


def main() -> None:
    require_pds_write()
    p2k = open_p2k()
    cur = p2k_payload(read_seem(p2k, 0x01C3))
    print('01C3 current', cur.hex(), flush=True)
    if len(cur) != 32:
        raise SystemExit('01C3 p2k length unexpected, refusing to proceed')
    expected_orig = bytes.fromhex('00000008080000000000000000') + b'\xff' * 19
    if cur != expected_orig:
        raise SystemExit('live 01C3 does not match the known original; refusing to guess blind')

    target = bytearray(cur)
    target[3] = 0xFF
    target[4] = 0xFF
    target = bytes(target)
    print('target 01C3', target.hex(), flush=True)

    wrap = scc_wrap(target)
    pt = wrap + b'\xff' * (SEEM_03FF_LOGICAL - 40)
    wr = write_seem(p2k, 0x03FF, pt)
    got = p2k_payload(read_seem(p2k, 0x03FF))
    print('03FF oracle write/read', wr[:16].hex(), got[:40].hex(), flush=True)
    if got[:40] != pt[:40]:
        raise SystemExit('03FF encrypt/decrypt identity failed; aborting before any flash write')

    print('flash cmd', p2k.cmd(0x0D, b'').hex(), flush=True)
    usb.util.dispose_resources(p2k.dev)
    if wait_pid(PID_FLASH, 15) is None:
        raise SystemExit('flash mode (6403) did not appear')

    er, ew = connect_loader()
    live = read_pds_block(er, ew)
    DIAG.joinpath('pds_live_01c3_ff.bin').write_bytes(live)
    ct = latest_payload(parse_pds(live), 0x03FF)
    head = ct[:40]
    print('new 01C3/01C4 ciphertext', head.hex(), flush=True)

    orig_area = parse_pds(ORIG_BLOCK)
    patched = live
    patched = replace_latest_payload(patched, 0x01C3, head)
    patched = replace_latest_payload(patched, 0x01C4, head)
    patched = replace_latest_payload(patched, 0x03FF, latest_payload(orig_area, 0x03FF))
    area2 = parse_pds(patched)
    if not area2.checksum_valid:
        restore_and_bail(er, ew, 'patched PDS checksum invalid')
    DIAG.joinpath('pds_01c3_ff.bin').write_bytes(patched)

    write_pds_block(er, ew, patched)
    verify = read_pds_block(er, ew)
    print('verify match', verify == patched, flush=True)
    if verify != patched:
        restore_and_bail(er, ew, 'NOR verify mismatch after write')

    restart(er, ew)
    if not wait_at(90):
        print('Phone did not re-enumerate as AT within 90s — rolling back.', flush=True)
        print('waiting (up to 10 min) for any Motorola USB PID to recover into...', flush=True)
        deadline = time.time() + 600
        last = None
        while time.time() < deadline:
            pids = tuple(sorted(mot_pids()))
            if pids != last:
                print('usb', [hex(p) for p in pids], flush=True)
                last = pids
            if pids:
                break
            time.sleep(0.2)
        else:
            raise SystemExit('CRITICAL: phone never re-enumerated on USB at all')
        hold_flash()
        er2, ew2 = connect_loader()
        restore_and_bail(er2, ew2, 'phone failed to boot to AT mode after patch')

    time.sleep(2)
    p2k = open_p2k()
    print('01C3 after', p2k_payload(read_seem(p2k, 0x01C3)).hex(), flush=True)
    print('01C4 after', p2k_payload(read_seem(p2k, 0x01C4)).hex(), flush=True)
    usb.util.dispose_resources(p2k.dev)
    print('done — check phone screen / insert SIM to test lock status', flush=True)


if __name__ == '__main__':
    main()
