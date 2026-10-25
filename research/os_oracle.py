"""Encrypt unlocked 20-byte subsidy payloads via OS SEEM 015F / A07B5A56.

Dumps the active PDS block, copies the resulting ciphertext onto 015C/015D,
restores 015F, and writes the full 128 KiB PDS block through Hitagi.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'research'))
sys.path.insert(0, str(ROOT / 'tools' / 'FlashTerminal'))

from p2k_probe import switch_p2k, P2K05, read_seem, VID, PID_P2K  # noqa: E402
from pds import parse_pds, latest_payload, replace_latest_payload, PDS_SIZE  # noqa: E402
from hitagi_pds import connect_loader, read_pds_block, write_pds_block, restart  # noqa: E402
from pds_write_guard import require_pds_write  # noqa: E402
import usb.core  # noqa: E402

SCRATCH = Path('/var/folders/w9/xz8w2l7s4c30fdp61p0bnxph0000gn/T/grok-goal-69e2a524b376/implementer')
UNLOCK_20 = b'\x00' * 20


def p2k_payload(raw: bytes) -> bytes:
    if raw and raw[0] == 0x82 and len(raw) > 13:
        return raw[13:]
    return raw


def write_seem(p2k: P2K05, seem: int, data: bytes) -> bytes:
    payload = (
        seem.to_bytes(2, 'big') + (1).to_bytes(2, 'big')
        + (0).to_bytes(2, 'big') + len(data).to_bytes(2, 'big') + data
    )
    return p2k.cmd(0x2F, payload)


def open_p2k() -> P2K05:
    dev = usb.core.find(idVendor=VID, idProduct=PID_P2K)
    if dev is None:
        switch_p2k()
        dev = usb.core.find(idVendor=VID, idProduct=PID_P2K)
    return P2K05(dev)


def wait_at() -> None:
    for i in range(30):
        dev = usb.core.find(idVendor=VID)
        print('usb', i, hex(dev.idProduct) if dev else None)
        if dev is not None and dev.idProduct == 0x6402:
            return
        time.sleep(1)
    raise SystemExit('no AT 6402')


def main() -> None:
    require_pds_write()
    log: list[str] = []

    def pr(*a) -> None:
        s = ' '.join(str(x) for x in a)
        print(s, flush=True)
        log.append(s)

    p2k = open_p2k()
    before = p2k_payload(read_seem(p2k, 0x015F))
    pr('015F before', before.hex())
    wr = write_seem(p2k, 0x015F, UNLOCK_20)
    pr('WRITE zeros', wr.hex())
    got = p2k_payload(read_seem(p2k, 0x015F))
    pr('015F after write', got.hex())
    if got != UNLOCK_20:
        raise SystemExit('015F encrypt/decrypt identity failed')
    pr('oracle identity OK')
    raw = p2k.cmd(0x0D, b'')
    pr('flash cmd', raw.hex())
    import usb.util
    usb.util.dispose_resources(p2k.dev)
    from p2k_probe import wait_pid
    from hitagi_pds import PID_FLASH
    if wait_pid(PID_FLASH, 15) is None:
        raise SystemExit('flash 6403 did not appear')
    pr('flash up')

    er, ew = connect_loader()
    live = read_pds_block(er, ew)
    pr('live PDS', len(live), live[:10].hex())
    (SCRATCH / 'pds_oracle.bin').write_bytes(live)
    area = parse_pds(live)
    ct = latest_payload(area, 0x015F)
    old15c = latest_payload(area, 0x015C)
    old15d = latest_payload(area, 0x015D)
    pr('015F CT len', len(ct) if ct else None, ct.hex() if ct else None)
    if ct is None or len(ct) != 32:
        raise SystemExit('oracle CT missing or wrong size')
    if old15c is None or len(old15c) != 32 or old15d is None or len(old15d) != 32:
        raise SystemExit('015C/015D stored size unexpected')
    if ct == old15c:
        raise SystemExit('oracle CT equals existing 015C; encrypt did not produce a new blob')

    backup = (ROOT / 'diagnostics' / 'nor_a000.bin').read_bytes()[0x40000:0x40000 + PDS_SIZE]
    (SCRATCH / 'pds_backup_block.bin').write_bytes(backup)
    patched = replace_latest_payload(live, 0x015C, ct)
    patched = replace_latest_payload(patched, 0x015D, ct)
    patched = replace_latest_payload(patched, 0x015F, latest_payload(parse_pds(backup), 0x015F))
    area2 = parse_pds(patched)
    if not area2.checksum_valid:
        raise SystemExit('patched PDS checksum invalid')
    if latest_payload(area2, 0x015C) != ct or latest_payload(area2, 0x015D) != ct:
        raise SystemExit('patched 015C/015D missing')
    (SCRATCH / 'pds_patched.bin').write_bytes(patched)
    (ROOT / 'diagnostics' / 'pds_patched.bin').write_bytes(patched)
    pr('patched checksum valid, 015C/015D <- oracle CT, 015F restored from backup')

    write_pds_block(er, ew, patched)
    verify = read_pds_block(er, ew)
    (SCRATCH / 'pds_written.bin').write_bytes(verify)
    pr('verify match', verify == patched)
    if verify != patched:
        pr('VERIFY MISMATCH — restoring backup block')
        write_pds_block(er, ew, backup)
        restart(er, ew)
        raise SystemExit('NOR verify failed, backup restored')
    restart(er, ew)
    wait_at()
    p2k = open_p2k()
    wr = write_seem(p2k, 0x015F, b'\xff' * 20)
    pr('restore 015F', wr.hex(), p2k_payload(read_seem(p2k, 0x015F)).hex())
    pr('015C', read_seem(p2k, 0x015C).hex())
    pr('015D', read_seem(p2k, 0x015D).hex())
    pr('01C3', read_seem(p2k, 0x01C3).hex())
    (SCRATCH / 'crypto-roundtrip.txt').write_text('\n'.join(log) + '\n')
    (SCRATCH / 'p2k-after-unlock.txt').write_text('\n'.join(log[-6:]) + '\n')


if __name__ == '__main__':
    main()
