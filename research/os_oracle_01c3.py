"""Encrypt 32-byte 01C3 payloads via OS SEEM 03FF (flags 0xA7, A07B5A56).

Writes scc_wrap(P2K 01C3) as the first 40 plaintext bytes of 03FF so the
first 40 stored bytes are IV=0 3DES-CBC of PT32||MAGIC||CRC32 — a complete
01C3 record. A second pass encrypts wrap(32 zeros) for the unlocked image.
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
from seem_crypt import scc_wrap, SCC_MAGIC  # noqa: E402
from pds_write_guard import require_pds_write  # noqa: E402
import usb.core  # noqa: E402

if __name__ == '__main__':
    require_pds_write()

SCRATCH = Path('/var/folders/w9/xz8w2l7s4c30fdp61p0bnxph0000gn/T/grok-goal-69e2a524b376/implementer')
DIAG = ROOT / 'diagnostics'
DUMP_01C3 = (DIAG / 'nor_a000.bin').read_bytes()
from pds import parse_pds as _parse  # noqa: E402
_ORIG = _parse(DUMP_01C3[0x40000:0x40000 + PDS_SIZE])
ORIG_01C3 = latest_payload(_ORIG, 0x01C3)
ORIG_03FF = latest_payload(_ORIG, 0x03FF)
SEEM_03FF_LOGICAL = 620


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


def flash_dump() -> bytes:
    import usb.util
    p2k = open_p2k()
    raw = p2k.cmd(0x0D, b'')
    print('flash cmd', raw.hex())
    usb.util.dispose_resources(p2k.dev)
    from p2k_probe import wait_pid
    from hitagi_pds import PID_FLASH
    if wait_pid(PID_FLASH, 15) is None:
        raise SystemExit('flash 6403 did not appear')
    er, ew = connect_loader()
    live = read_pds_block(er, ew)
    return er, ew, live


def main() -> None:
    require_pds_write()
    mode = sys.argv[1] if len(sys.argv) > 1 else 'known'
    log: list[str] = []

    def pr(*a) -> None:
        s = ' '.join(str(x) for x in a)
        print(s, flush=True)
        log.append(s)

    p2k = open_p2k()
    cur = p2k_payload(read_seem(p2k, 0x01C3))
    pr('01C3 p2k', len(cur), cur.hex())
    if len(cur) != 32:
        raise SystemExit('01C3 p2k length')
    if mode == 'known':
        target = cur
        tag = 'known'
    elif mode == 'unlock':
        target = b'\x00' * 32
        tag = 'unlock'
    else:
        raise SystemExit('mode known|unlock')
    wrapped = scc_wrap(target)
    pr('wrap', wrapped.hex())
    pr('magic', wrapped[32:36].hex(), 'crc', wrapped[36:40].hex())
    if wrapped[32:36] != SCC_MAGIC or len(wrapped) != 40:
        raise SystemExit('wrap malformed')
    pt = wrapped + b'\xff' * (SEEM_03FF_LOGICAL - 40)
    before = p2k_payload(read_seem(p2k, 0x03FF))
    pr('03FF before len', len(before), before[:40].hex())
    wr = write_seem(p2k, 0x03FF, pt)
    pr('WRITE 03FF', wr[:24].hex())
    got = p2k_payload(read_seem(p2k, 0x03FF))
    pr('03FF after len', len(got), got[:40].hex())
    if got[:40] != pt[:40]:
        raise SystemExit('03FF encrypt/decrypt identity failed on wrap prefix')
    pr('oracle identity OK')
    import usb.util
    usb.util.dispose_resources(p2k.dev)

    er, ew, live = flash_dump()
    pr('live PDS', len(live), live[:10].hex())
    (SCRATCH / f'pds_03ff_{tag}.bin').write_bytes(live)
    area = parse_pds(live)
    ct = latest_payload(area, 0x03FF)
    if ct is None or len(ct) != 632:
        raise SystemExit(f'03FF stored {None if ct is None else len(ct)}')
    head = ct[:40]
    pr('03FF CT40', head.hex())
    (DIAG / f'03ff_wrap_{tag}_ct.bin').write_bytes(head)
    (SCRATCH / f'03ff_wrap_{tag}_ct.bin').write_bytes(head)
    if tag == 'known':
        pr('dump 01C3', ORIG_01C3.hex() if ORIG_01C3 else None)
        pr('match dump 01C3', head == ORIG_01C3)
        (DIAG / '03ff_wrap_01c3_ct.bin').write_bytes(head)
        (SCRATCH / 'crypto-roundtrip.txt').write_text('\n'.join(log) + '\n')
        restart(er, ew)
        wait_at()
        (SCRATCH / 'os-oracle-01c3-known.txt').write_text('\n'.join(log) + '\n')
        return

    if ORIG_01C3 is None or ORIG_03FF is None:
        raise SystemExit('original 01C3/03FF missing')
    patched = live
    patched = replace_latest_payload(patched, 0x01C3, head)
    patched = replace_latest_payload(patched, 0x01C4, head)
    patched = replace_latest_payload(patched, 0x03FF, ORIG_03FF)
    area2 = parse_pds(patched)
    if not area2.checksum_valid:
        raise SystemExit('patched PDS checksum invalid')
    if latest_payload(area2, 0x01C3) != head:
        raise SystemExit('patched 01C3 missing')
    (DIAG / 'pds_patched_01c3.bin').write_bytes(patched)
    (SCRATCH / 'pds_patched_01c3.bin').write_bytes(patched)
    pr('patched checksum valid, 01C3/01C4 <- wrap(zeros) CT, 03FF restored')

    write_pds_block(er, ew, patched)
    verify = read_pds_block(er, ew)
    (SCRATCH / 'pds_written_01c3.bin').write_bytes(verify)
    pr('verify match', verify == patched)
    if verify != patched:
        backup = DUMP_01C3[0x40000:0x40000 + PDS_SIZE]
        pr('VERIFY MISMATCH — restoring original dump block')
        write_pds_block(er, ew, backup)
        restart(er, ew)
        raise SystemExit('NOR verify failed, dump block restored')
    restart(er, ew)
    wait_at()
    p2k = open_p2k()
    pr('01C3', p2k_payload(read_seem(p2k, 0x01C3)).hex())
    pr('01C4', p2k_payload(read_seem(p2k, 0x01C4)).hex())
    pr('015C', read_seem(p2k, 0x015C).hex())
    pr('015D', read_seem(p2k, 0x015D).hex())
    (SCRATCH / 'crypto-roundtrip.txt').write_text('\n'.join(log) + '\n')
    (SCRATCH / 'p2k-after-unlock.txt').write_text('\n'.join(log[-6:]) + '\n')


if __name__ == '__main__':
    main()
