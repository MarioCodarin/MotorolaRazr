"""Read-only P2K probe: SEEM reads and a small SRAM MEMACS sample.

Does not write SEEMs or flash.
"""

from __future__ import annotations

import glob
import sys
import time
from pathlib import Path

import serial
import usb.core
import usb.util

VID = 0x22B8
PID_AT = 0x6402
PID_P2K = 0x6401
_modems = sorted(glob.glob('/dev/cu.usbmodem*'))
MODEM = _modems[0] if _modems else ''
TIMEOUT = 5000
SEEMS = (0x015C, 0x015D, 0x01C3, 0x01C4, 0x0163, 0x0117)


def wait_pid(pid: int, seconds: float = 12.0):
    deadline = time.time() + seconds
    while time.time() < deadline:
        dev = usb.core.find(idVendor=VID, idProduct=pid)
        if dev is not None:
            return dev
        time.sleep(0.25)
    return None


def switch_p2k() -> usb.core.Device:
    if usb.core.find(idVendor=VID, idProduct=PID_P2K):
        print('already in P2K')
        return usb.core.find(idVendor=VID, idProduct=PID_P2K)
    if not MODEM:
        raise SystemExit('no /dev/cu.usbmodem* and the phone is not already 22b8:6401')
    ser = serial.Serial(MODEM, 115200, timeout=1)
    ser.write(b'AT\r')
    time.sleep(0.3)
    print('AT', ser.read(64))
    ser.write(b'AT+MODE=8\r')
    ser.close()
    print('waiting for P2K 22b8:6401')
    dev = wait_pid(PID_P2K, 15)
    if dev is None:
        raise SystemExit('P2K device did not appear')
    print('P2K up')
    return dev


class P2K05:
    def __init__(self, dev):
        self.dev = dev
        self.pid = 1
        cfg = dev.get_active_configuration()
        intf = usb.util.find_descriptor(cfg, bInterfaceNumber=1)
        usb.util.claim_interface(dev, 1)
        self.ep_out = usb.util.find_descriptor(
            intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT)
        self.ep_in = usb.util.find_descriptor(
            intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN)

    def cmd(self, code: int, payload: bytes) -> bytes:
        self.pid = (self.pid + 1) & 0xFFF
        packet = (
            self.pid.to_bytes(2, 'big') + code.to_bytes(2, 'big')
            + b'\x00\x00\x00\x00\x00\x00' + len(payload).to_bytes(2, 'big') + payload
        )
        self.ep_out.write(packet, TIMEOUT)
        return bytes(self.ep_in.read(0x1000, TIMEOUT))


def read_seem(p2k: P2K05, seem: int, rec: int = 1) -> bytes:
    payload = seem.to_bytes(2, 'big') + rec.to_bytes(2, 'big') + b'\x00\x00\x00\x00'
    return p2k.cmd(0x20, payload)


def memacs(p2k: P2K05, addr: int, step: int) -> bytes:
    payload = addr.to_bytes(4, 'big') + step.to_bytes(2, 'big') + b'\x00\x00'
    return p2k.cmd(0x16, payload)


def main() -> None:
    out = Path('diagnostics')
    dev = switch_p2k()
    p2k = P2K05(dev)
    for seem in SEEMS:
        raw = read_seem(p2k, seem)
        print(f'SEEM {seem:04X} raw_len={len(raw)} {raw[:24].hex()}')
    step = 0x100
    for addr in (0x80000000, 0x80001000, 0xA0040000, 0x00000000):
        try:
            chunk = memacs(p2k, addr, step)
        except usb.core.USBError as exc:
            print(f'MEMACS {addr:08X} USBError {exc}')
            continue
        print(f'MEMACS {addr:08X} len={len(chunk)} {chunk[:24].hex()}')
        (out / f'live_memacs_{addr:08X}.bin').write_bytes(chunk)


if __name__ == '__main__':
    sys.exit(main())
