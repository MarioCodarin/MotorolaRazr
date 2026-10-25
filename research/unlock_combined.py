"""Combined attempt: clear 01C3/01C4 AND 015C/015D in the SAME write.

Every previous attempt changed only one of these two record pairs at a
time. Both individual changes are independently known to boot
successfully (not corrupt the structure):
  - 01C3/01C4 bytes[3:5] 08,08 -> 00,00   (unlock_01c3_byte4.py family)
  - 015C/015D -> 20 zero bytes            (os_oracle.py)
...yet each alone leaves the phone locked. This tests the hypothesis
that the firmware cross-validates the two records against each other,
so only a coordinated change could look consistent.

Uses the proven 03FF oracle for 01C3/01C4 and the 015F oracle for
015C/015D, patches both into a single PDS block, writes once, and
rolls back fully on any failure (checksum invalid / NOR verify
mismatch / phone fails to re-enumerate as AT mode).
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
import FlashTerminal as ft  # noqa: E402
from pds import parse_pds, latest_payload, replace_latest_payload, PDS_SIZE  # noqa: E402
from p2k_probe import read_seem, wait_pid, VID  # noqa: E402
from os_oracle import p2k_payload, open_p2k, write_seem  # noqa: E402
from hitagi_pds import connect_loader, read_pds_block, write_pds_block, PID_FLASH  # noqa: E402
from seem_crypt import scc_wrap  # noqa: E402
from restore_pds_backup import mot_pids, hold_flash  # noqa: E402
from pds_write_guard import require_pds_write  # noqa: E402

if __name__ == '__main__':
    require_pds_write()

DIAG = ROOT / 'diagnostics'
ORIG_BLOCK = (DIAG / 'nor_a000.bin').read_bytes()[0x40000:0x40000 + PDS_SIZE]
SEEM_03FF_LOGICAL = 620
UNLOCK_20 = b'\x00' * 20


def wait_at(seconds: float) -> bool:
    deadline = time.time() + seconds
    last = None
    while time.time() < deadline:
        dev = usb.core.find(idVendor=VID)
        pid = dev.idProduct if dev else None
        if pid != last:
            print('usb', hex(pid) if pid else None, flush=True)
            last = pid
        if pid == 0x6402:
            return True
        time.sleep(1)
    return False


def soft_restart(er, ew) -> None:
    try:
        ft.mfp_cmd(er, ew, 'RESTART')
    except Exception as exc:
        print('restart cmd', exc, flush=True)


def recover_to_loader():
    print('waiting (up to 10 min) for any Motorola USB PID...', flush=True)
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
    return connect_loader()


def restore_and_bail(er, ew, reason: str) -> None:
    print('ROLLING BACK:', reason, flush=True)
    write_pds_block(er, ew, ORIG_BLOCK)
    verify = read_pds_block(er, ew)
    print('rollback verify match', verify == ORIG_BLOCK, flush=True)
    soft_restart(er, ew)
    if not wait_at(90):
        er2, ew2 = recover_to_loader()
        write_pds_block(er2, ew2, ORIG_BLOCK)
        verify2 = read_pds_block(er2, ew2)
        print('second rollback verify match', verify2 == ORIG_BLOCK, flush=True)
        soft_restart(er2, ew2)
        if not wait_at(90):
            raise SystemExit('CRITICAL: phone did not return to AT mode after rollback restart')
    raise SystemExit(f'aborted and rolled back: {reason}')


def main() -> None:
    require_pds_write()
    p2k = open_p2k()
    cur_01c3 = p2k_payload(read_seem(p2k, 0x01C3))
    print('01C3 current', cur_01c3.hex(), flush=True)
    expected_orig = bytes.fromhex('00000008080000000000000000') + b'\xff' * 19
    if cur_01c3 != expected_orig:
        raise SystemExit('live 01C3 does not match the known original; refusing to guess blind')

    # --- Step 1: 01C3/01C4 new ciphertext via the 03FF oracle ---
    target_01c3 = bytearray(cur_01c3)
    target_01c3[3] = 0x00
    target_01c3[4] = 0x00
    target_01c3 = bytes(target_01c3)
    print('target 01C3', target_01c3.hex(), flush=True)

    wrap = scc_wrap(target_01c3)
    pt = wrap + b'\xff' * (SEEM_03FF_LOGICAL - 40)
    wr = write_seem(p2k, 0x03FF, pt)
    got = p2k_payload(read_seem(p2k, 0x03FF))
    print('03FF oracle write/read', wr[:16].hex(), got[:40].hex(), flush=True)
    if got[:40] != pt[:40]:
        raise SystemExit('03FF encrypt/decrypt identity failed; aborting before any flash write')

    # --- Step 2: 015C/015D new ciphertext via the 015F oracle ---
    before_015f = p2k_payload(read_seem(p2k, 0x015F))
    print('015F before', before_015f.hex(), flush=True)
    wr2 = write_seem(p2k, 0x015F, UNLOCK_20)
    got2 = p2k_payload(read_seem(p2k, 0x015F))
    print('015F oracle write/read', wr2[:16].hex(), got2.hex(), flush=True)
    if got2 != UNLOCK_20:
        raise SystemExit('015F encrypt/decrypt identity failed; aborting before any flash write')

    print('flash cmd', p2k.cmd(0x0D, b'').hex(), flush=True)
    usb.util.dispose_resources(p2k.dev)
    if wait_pid(PID_FLASH, 15) is None:
        raise SystemExit('flash mode (6403) did not appear')

    er, ew = connect_loader()
    live = read_pds_block(er, ew)
    DIAG.joinpath('pds_live_combined.bin').write_bytes(live)
    area_live = parse_pds(live)

    ct_01c3 = latest_payload(area_live, 0x03FF)[:40]
    ct_015c = latest_payload(area_live, 0x015F)
    print('new 01C3/01C4 ciphertext', ct_01c3.hex(), flush=True)
    print('new 015C/015D ciphertext', ct_015c.hex(), flush=True)
    if ct_015c is None or len(ct_015c) != 32:
        raise SystemExit('015F stored ciphertext wrong size')

    orig_area = parse_pds(ORIG_BLOCK)
    orig_015c = latest_payload(orig_area, 0x015C)
    if ct_015c == orig_015c:
        raise SystemExit('oracle CT equals existing 015C; encrypt did not produce a new blob')

    patched = live
    patched = replace_latest_payload(patched, 0x01C3, ct_01c3)
    patched = replace_latest_payload(patched, 0x01C4, ct_01c3)
    patched = replace_latest_payload(patched, 0x015C, ct_015c)
    patched = replace_latest_payload(patched, 0x015D, ct_015c)
    patched = replace_latest_payload(patched, 0x03FF, latest_payload(orig_area, 0x03FF))
    patched = replace_latest_payload(patched, 0x015F, latest_payload(orig_area, 0x015F))

    area2 = parse_pds(patched)
    if not area2.checksum_valid:
        restore_and_bail(er, ew, 'patched PDS checksum invalid')
    if (latest_payload(area2, 0x01C3) != ct_01c3 or latest_payload(area2, 0x01C4) != ct_01c3
            or latest_payload(area2, 0x015C) != ct_015c or latest_payload(area2, 0x015D) != ct_015c):
        restore_and_bail(er, ew, 'patched records missing/mismatched after replace')
    DIAG.joinpath('pds_combined.bin').write_bytes(patched)
    print('patched checksum valid, all four records updated consistently', flush=True)

    write_pds_block(er, ew, patched)
    verify = read_pds_block(er, ew)
    print('verify match', verify == patched, flush=True)
    if verify != patched:
        restore_and_bail(er, ew, 'NOR verify mismatch after write')

    soft_restart(er, ew)
    if not wait_at(60):
        print('Phone did not re-enumerate as AT within 60s — recovering and rolling back.', flush=True)
        er2, ew2 = recover_to_loader()
        restore_and_bail(er2, ew2, 'phone failed to boot to AT mode after patch')

    time.sleep(2)
    p2k = open_p2k()
    print('01C3 after', p2k_payload(read_seem(p2k, 0x01C3)).hex(), flush=True)
    print('01C4 after', p2k_payload(read_seem(p2k, 0x01C4)).hex(), flush=True)
    usb.util.dispose_resources(p2k.dev)
    print('BOOTED OK. Please check the phone screen for lock status now.', flush=True)


if __name__ == '__main__':
    main()
