"""Drive ArgonLV SCC (3DES-CBC) via Hitagi. No NOR ERASE/BIN."""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools' / 'FlashTerminal'))
sys.path.insert(0, str(ROOT / 'research'))

import FlashTerminal as ft  # noqa: E402
from p2k_probe import VID, PID_P2K, wait_pid  # noqa: E402

PID_FLASH = 0x6403
LOADER = ROOT / 'tools' / 'Hitagi' / 'hitagi.bin'
SCC_BASE = 0x53FAC000
PARAM = 0x8001F000
STX, ETX, RS = 0x02, 0x03, 0x1E


def p2k_to_flash() -> None:
    import usb.core
    from p2k_probe import P2K05, MODEM
    import serial
    flash = usb.core.find(idVendor=VID, idProduct=PID_FLASH)
    if flash is not None:
        print('already flash')
        return
    at = usb.core.find(idVendor=VID, idProduct=0x6402)
    if at is not None:
        try:
            ser = serial.Serial(MODEM, 115200, timeout=0.5)
            ser.write(b'AT+MODE=24\r')
            ser.close()
            print('AT+MODE=24')
        except Exception as exc:
            print('AT+MODE=24 failed', exc)
        flash = wait_pid(PID_FLASH, 6)
        if flash is not None:
            print('flash up via AT')
            return
    if usb.core.find(idVendor=VID, idProduct=PID_P2K) is None:
        from p2k_probe import switch_p2k
        switch_p2k()
    dev = usb.core.find(idVendor=VID, idProduct=PID_P2K)
    if dev is None:
        raise SystemExit('P2K device missing')
    p2k = P2K05(dev)
    raw = p2k.cmd(0x0D, b'')
    print('flash cmd', raw.hex())
    flash = wait_pid(PID_FLASH, 15)
    if flash is None:
        raise SystemExit('flash 6403 did not appear')
    print('flash up')


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
        data = body[2:2 + size]
        return bytes(data)
    if body.endswith(bytes([ETX])):
        return bytes(body[:-1])
    return bytes(body)


def u32s(words: list[int]) -> bytes:
    return b''.join(w.to_bytes(4, 'big') for w in words)


def read_mem(er, ew, addr: int, size: int) -> bytes:
    resp = bytes(ft.mfp_cmd(er, ew, 'READ', f'{addr:08X},{size:04X}'.encode()))
    return parse_read(resp)


def poke(er, ew, addr: int, data: bytes) -> None:
    ack = ft.mfp_addr(er, ew, addr)
    print('ADDR', hex(addr), bytes(ack)[:24])
    ack = ft.mfp_bin(er, ew, data)
    print('BIN', len(data), bytes(ack)[:24])


def scc_run(er, ew, mode: int, data: bytes, iv: bytes = b'\0' * 8) -> tuple[int, int, int, int, bytes]:
    if len(iv) != 8:
        raise ValueError('IV must be 8 bytes')
    if len(data) % 8:
        raise ValueError('data must be 8-byte aligned')
    iv0 = int.from_bytes(iv[:4], 'big')
    iv1 = int.from_bytes(iv[4:], 'big')
    payload = u32s([mode, len(data), iv0, iv1]) + data
    poke(er, ew, PARAM, payload)
    ack = ft.mfp_cmd(er, ew, 'SCCRUN')
    print('SCCRUN', bytes(ack)[:32])
    out = read_mem(er, ew, PARAM, 16 + len(data))
    status = int.from_bytes(out[0:4], 'big')
    err = int.from_bytes(out[4:8], 'big')
    polls = int.from_bytes(out[8:12], 'big')
    cfg = int.from_bytes(out[12:16], 'big')
    return status, err, polls, cfg, out[16:16 + len(data)]


def main() -> None:
    ft.set_logging_configuration(True)
    ft.timeout_read = 8000
    out = Path('diagnostics')
    p2k_to_flash()
    er, ew = ft.usb_init(ft.usb_devices, 'flash')
    if not er or not ew:
        raise SystemExit('no flash endpoints')
    print('RQHW boot', ft.mfp_cmd(er, ew, 'RQHW'))
    print('uploading', LOADER)
    ft.mfp_upload_binary_to_addr(er, ew, str(LOADER), 0x80000000, 0x80000038, True)
    print('RQHW loader', ft.mfp_cmd(er, ew, 'RQHW'))
    print('RQSW', ft.mfp_cmd(er, ew, 'RQSW'))
    smn_base = SCC_BASE + 0x1000
    print('Hitagi SMN', read_mem(er, ew, smn_base, 0x10).hex())

    regs = read_mem(er, ew, SCC_BASE, 0x30)
    print('SCC regs', regs.hex())
    (out / 'scc_regs.bin').write_bytes(regs)
    smn = read_mem(er, ew, SCC_BASE + 0x1000, 0x40)
    print('SMN', smn.hex())
    (out / 'scc_smn.bin').write_bytes(smn)
    red = read_mem(er, ew, SCC_BASE + 0x400, 0x200)
    black = read_mem(er, ew, SCC_BASE + 0x800, 0x200)
    (out / 'scc_red.bin').write_bytes(red)
    (out / 'scc_black.bin').write_bytes(black)
    print('RED head', red[:64].hex())
    print('BLK head', black[:64].hex())

    from pds import parse_pds, latest_payload, PDS_SIZE
    image = (out / 'nor_a000.bin').read_bytes()
    area = parse_pds(image[0x40000:0x40000 + PDS_SIZE])
    blob = latest_payload(area, 0x01C3)
    p2k = (out / '01c3_0001.seem').read_bytes()
    print('PDS 01C3', len(blob), blob.hex())
    print('P2K 01C3', p2k.hex())

    blob15 = latest_payload(area, 0x015C)
    trials = [
        ('dec-ivhead-ct32', 7, blob[8:], blob[:8]),
        ('dec-iv0-all40', 7, blob, b'\0' * 8),
        ('dec-015c-ivhead', 7, blob15[8:], blob15[:8]),
        ('dec-015c-iv0', 7, blob15, b'\0' * 8),
    ]
    for name, mode, data, iv in trials:
        try:
            status, err, polls, cfg, plain = scc_run(er, ew, mode, data, iv)
        except Exception as exc:
            print(name, 'ERR', exc)
            continue
        print(name, 'st', hex(status), 'err', hex(err), 'polls_smn', hex(polls), 'smn', hex(cfg))
        print(' ', plain.hex())
        (out / f'scc_{name}.bin').write_bytes(plain)
        if p2k in plain or plain[:32] == p2k or plain[:8] == p2k[:8]:
            print('  MATCH P2K')

    print('RESTART')
    try:
        ft.mfp_cmd(er, ew, 'RESTART')
    except Exception as exc:
        print('restart', exc)


if __name__ == '__main__':
    main()
