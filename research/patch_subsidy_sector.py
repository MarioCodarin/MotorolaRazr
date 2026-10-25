"""Program or restore the subsidy halfword at flash 0xA0855D70.

Default is a local check of diagnostics/nor_a000.bin. No USB traffic.
The check accepts a 32 MiB dump of firmware R26111LD_U_96.A0.0ER whose
code sector 0xA0840000 still hashes to the tested original. It does not
require this handset's full-image digest. PDS differs per phone.

  python3 research/patch_subsidy_sector.py
  python3 research/patch_subsidy_sector.py --write
  python3 research/patch_subsidy_sector.py --restore
  python3 research/patch_subsidy_sector.py --replay-saved

--write and --restore require the phone to already be USB 22b8:6403.
They do not send AT+MODE=24 and they do not call write_pds_block.
They send ERASE twice (buffer mode) and never a third time.
They do not modify diagnostics/nor_a000.bin.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKUP = ROOT / 'diagnostics' / 'nor_a000.bin'
LOADER = ROOT / 'tools' / 'Hitagi' / 'hitagi.bin'
LIVE_COPY = ROOT / 'diagnostics' / 'sector_a0840000_before.bin'

FIRMWARE_ID = b'R26111LD_U_96.A0.0ER'
SECTOR_SHA256 = 'cbe48aae37439587731673f4d95a9d20d5b7e2e50f8b7a409ce068f2ae35e7a5'
PATCHED_SECTOR_SHA256 = 'a0f028d3069d76d7d0fc89d102d7dd30e08a226e2bfc56164407ff54a84482b9'
VID = 0x22B8
PID_FLASH = 0x6403
SECTOR_ADDR = 0xA0840000
SECTOR_FILE = 0x840000
SECTOR_SIZE = 0x20000
PATCH_INDEX = 0x15D70
CHUNK = 0x0800
BIN_CHUNK = 32
STX, ETX, RS = 0x02, 0x03, 0x1E


def log(msg: str) -> None:
    print(msg, flush=True)


def load_backup_sector() -> bytes:
    if not BACKUP.is_file():
        raise SystemExit(f'STOP missing {BACKUP}. Dump NOR first. See docs/guide.md.')
    blob = BACKUP.read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    log(f'backup sha256 {digest}')
    if len(blob) != 0x2000000:
        short = ''
        if len(blob) == 0x2000000 - 512:
            short = (
                ' A step of 0x300 stops 512 bytes early.'
                ' Use end 0xA2000000 and step 0x200.'
            )
        raise SystemExit(f'STOP backup size {len(blob)}.{short}')
    if FIRMWARE_ID not in blob:
        raise SystemExit(f'STOP backup has no {FIRMWARE_ID.decode()} ident')
    sector = blob[SECTOR_FILE:SECTOR_FILE + SECTOR_SIZE]
    half = sector[PATCH_INDEX:PATCH_INDEX + 2]
    log(f'backup halfword at file 0x855D70 {half.hex()}')
    if half != b'\xd0\x07':
        raise SystemExit('STOP backup halfword is not d0 07')
    sector_digest = hashlib.sha256(sector).hexdigest()
    log(f'backup sector sha256 {sector_digest}')
    if sector_digest != SECTOR_SHA256:
        raise SystemExit(
            'STOP sector hash is not the tested R26111LD_U_96.A0.0ER code sector'
        )
    return sector


def build_patch(original: bytes) -> bytes:
    patched = bytearray(original)
    if patched[PATCH_INDEX:PATCH_INDEX + 2] != b'\xd0\x07':
        raise SystemExit('STOP sector halfword is not d0 07')
    patched[PATCH_INDEX] = 0xE0
    diffs = [i for i, (a, b) in enumerate(zip(original, patched)) if a != b]
    if diffs != [PATCH_INDEX] or bytes(patched[PATCH_INDEX:PATCH_INDEX + 2]) != b'\xe0\x07':
        raise SystemExit(f'STOP patch diff {diffs[:8]}')
    log(
        'patched sector sha256 '
        f'{hashlib.sha256(patched).hexdigest()} single byte 0x15D70 d0 -> e0'
    )
    return bytes(patched)


def parse_read(resp: bytes) -> bytes:
    if not resp:
        return b''
    try:
        start = resp.index(STX)
    except ValueError:
        return resp
    body = resp[start + 1:]
    if RS in body:
        body = body[body.index(RS) + 1:]
    if len(body) >= 2:
        size = (body[0] << 8) | body[1]
        return bytes(body[2:2 + size])
    if body.endswith(bytes([ETX])):
        return bytes(body[:-1])
    return bytes(body)


def connect_and_program(
    target: bytes, label: str, allowed: bytes, *, force: bool = False,
) -> None:
    import usb.core
    sys.path.insert(0, str(ROOT / 'tools' / 'FlashTerminal'))
    import FlashTerminal as ft

    def product_id():
        dev = usb.core.find(idVendor=VID)
        if dev is None:
            return None, ''
        try:
            name = dev.product or ''
        except Exception:
            name = ''
        return dev.idProduct, name

    pid, name = product_id()
    log(f'product id 0x{pid:04X} {name}' if pid is not None else 'product id absent')
    if pid != PID_FLASH:
        raise SystemExit('STOP phone is not 22b8:6403. No AT+MODE=24. No RESTART.')

    ft.set_logging_configuration(False)
    ft.timeout_read = 8000
    ft.timeout_write = 8000
    er, ew = ft.usb_init(ft.usb_devices, 'flash')
    if not er or not ew:
        raise SystemExit('STOP no flash endpoints')
    boot = bytes(ft.mfp_cmd(er, ew, 'RQHW'))
    log(f'RQHW boot {boot!r}')
    if b'FFFF' not in boot:
        log(f'uploading {LOADER.name} to RAM')
        ft.mfp_upload_binary_to_addr(er, ew, str(LOADER), 0x80000000, 0x80000038, True)
        log(f'RQHW loader {bytes(ft.mfp_cmd(er, ew, "RQHW"))!r}')
    log(f'RQSW {bytes(ft.mfp_cmd(er, ew, "RQSW"))!r}')
    try:
        rqfi = bytes(ft.mfp_cmd(er, ew, 'RQFI'))
    except Exception as exc:
        raise SystemExit(f'STOP RQFI failed before ERASE: {exc!r}') from exc
    log(f'RQFI {rqfi!r}')
    if not rqfi or b'ERR' in rqfi:
        raise SystemExit('STOP RQFI rejected. No ERASE.')

    def read_mem(addr: int, size: int) -> bytes:
        resp = bytes(ft.mfp_cmd(er, ew, 'READ', f'{addr:08X},{size:04X}'.encode()))
        data = parse_read(resp)
        if len(data) != size:
            raise IOError(f'READ {addr:08X},{size:04X} got {len(data)} raw={resp[:24]!r}')
        return data

    chunks = []
    off = 0
    while off < SECTOR_SIZE:
        n = min(CHUNK, SECTOR_SIZE - off)
        chunks.append(read_mem(SECTOR_ADDR + off, n))
        off += n
        if off % 0x8000 == 0:
            log(f'READ {SECTOR_ADDR:08X}+{off:05X}')
    live = b''.join(chunks)
    if live == target:
        log(f'live sector already matches {label}. No ERASE.')
        return
    if live != allowed and not force:
        mismatch = next((i for i, (a, b) in enumerate(zip(live, allowed)) if a != b), None)
        where = 'length' if mismatch is None else f'+{mismatch:05X}'
        log(f'STOP live sector is neither the backup nor the patched image ({where}). No ERASE.')
        log(f'If {LIVE_COPY.name} is the pre-erase sector, run --replay-saved.')
        raise SystemExit(2)
    if not force:
        LIVE_COPY.write_bytes(live)
        log(f'saved live sector {LIVE_COPY} sha256 {hashlib.sha256(live).hexdigest()}')
    else:
        log(f'replay keeps {LIVE_COPY.name}. live sha256 {hashlib.sha256(live).hexdigest()}')

    def bin_sector(data: bytes, bin_label: str) -> None:
        ft.timeout_write = 30000
        ft.timeout_read = 30000
        ack = bytes(ft.mfp_addr(er, ew, SECTOR_ADDR))
        log(f'{bin_label} ADDR {SECTOR_ADDR:08X} {ack[:24]!r}')
        if b'ERR' in ack:
            raise IOError(f'{bin_label} ADDR rejected')
        pos = 0
        while pos < SECTOR_SIZE:
            chunk = data[pos:pos + BIN_CHUNK]
            if len(chunk) != BIN_CHUNK:
                raise IOError(f'{bin_label} short chunk at {pos:05X}')
            ack = bytes(ft.mfp_bin(er, ew, chunk))
            if pos == 0 or (pos & 0x1FFF) == 0:
                log(f'{bin_label} BIN {pos:05X}+{len(chunk):04X} {ack[:20]!r}')
            if b'ERR' in ack:
                raise IOError(f'{bin_label} BIN error at {pos:05X}: {ack[:40]!r}')
            if pos == 0:
                time.sleep(8)
            pos += BIN_CHUNK

    def read_back() -> bytes:
        parts = []
        pos = 0
        while pos < SECTOR_SIZE:
            n = min(CHUNK, SECTOR_SIZE - pos)
            parts.append(read_mem(SECTOR_ADDR + pos, n))
            pos += n
        return b''.join(parts)

    ft.timeout_write = 30000
    ft.timeout_read = 30000
    e1 = bytes(ft.mfp_cmd(er, ew, 'ERASE'))
    e2 = bytes(ft.mfp_cmd(er, ew, 'ERASE'))
    log(f'ERASE 1 {e1[:24]!r}')
    log(f'ERASE 2 {e2[:24]!r}')
    if b'ERR' in e1 or b'ERR' in e2:
        raise SystemExit('STOP ERASE rejected. No third ERASE. No BIN.')

    def rollback(why: str) -> None:
        log(why)
        try:
            bin_sector(live, 'rollback')
            rolled = read_back()
        except BaseException as exc:
            log(f'rollback failed {exc!r}. sector may be incomplete.')
            log('next 6403 session must rewrite the saved sector before any other edit.')
            raise
        if rolled != live:
            log('ROLLBACK MISMATCH. sector may be incomplete. phone left in the loader.')
            raise SystemExit(3)
        log('rollback readback matches the saved live sector')

    try:
        bin_sector(target, label)
        back = read_back()
    except SystemExit as exc:
        if exc.code != 3:
            rollback(f'exit during program {exc!r}. rewriting the saved live sector. no extra ERASE.')
        raise
    except Exception as exc:
        rollback(f'write failed {exc!r}. rewriting the saved live sector. no extra ERASE.')
        raise SystemExit(4) from exc
    if back != target:
        half = back[PATCH_INDEX:PATCH_INDEX + 2].hex()
        rollback(f'readback mismatch halfword {half}. rewriting the saved live sector. no extra ERASE.')
        raise SystemExit(3)
    log(f'readback matches {label}. halfword {back[PATCH_INDEX:PATCH_INDEX + 2].hex()}')
    try:
        ft.mfp_cmd(er, ew, 'RESTART')
        log('RESTART sent')
    except Exception as exc:
        log(f'RESTART send {exc!r}')
    for i in range(30):
        pid, name = product_id()
        shown = 'absent' if pid is None else f'0x{pid:04X} {name}'
        log(f'usb {i} {shown}')
        if pid == 0x6402:
            log('modem 6402 enumerated. AT+CREG? was not sent.')
            return
        time.sleep(1)
    log('after RESTART the phone did not stay on 6402. registration was not queried.')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--write', action='store_true', help='program e0 07. phone must be 22b8:6403')
    group.add_argument('--restore', action='store_true', help='program the backup sector. phone must be 22b8:6403')
    group.add_argument(
        '--replay-saved', action='store_true',
        help='program diagnostics/sector_a0840000_before.bin. phone must be 22b8:6403',
    )
    args = parser.parse_args()
    original = load_backup_sector()
    patched = build_patch(original)
    patched_digest = hashlib.sha256(patched).hexdigest()
    log(f'patched sector sha256 {patched_digest}')
    if patched_digest != PATCHED_SECTOR_SHA256:
        raise SystemExit('STOP patched sector hash drifted')
    if not args.write and not args.restore and not args.replay_saved:
        log('local check only. no USB command was sent.')
        return
    if args.replay_saved:
        if not LIVE_COPY.is_file():
            raise SystemExit(f'STOP missing {LIVE_COPY}')
        saved = LIVE_COPY.read_bytes()
        if saved == original:
            label = 'replay original'
        elif saved == patched:
            label = 'replay patch'
        else:
            raise SystemExit('STOP saved sector is neither the backup nor the patched image')
        connect_and_program(saved, label, saved, force=True)
        return
    if args.write:
        if original[PATCH_INDEX:PATCH_INDEX + 2] != b'\xd0\x07':
            raise SystemExit('STOP refusing to write')
        connect_and_program(patched, 'patch', original)
        return
    connect_and_program(original, 'restore', patched)


if __name__ == '__main__':
    main()
