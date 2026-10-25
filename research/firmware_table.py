"""Read-only inspection of a V3xx firmware protection table.

This does not produce a flashable image or modify the phone.
"""

from dataclasses import dataclass
from pathlib import Path
import argparse
import hashlib


PROTECTED_IDS = (
    0x015E, 0x015B, 0x005F, 0x015D, 0x015C, 0x0161, 0x0189,
    0x01C3, 0x01C4, 0x01C5, 0x01C6, 0x01C7, 0x01F8, 0x01F9, 0x01FA,
)
SUBSIDY_IDS = (0x015C, 0x015D, 0x01C3, 0x01C4)


@dataclass(frozen=True)
class ProtectedTable:
    address: int
    handler: int
    entries: dict[int, int]


def locate_protected_table(image: bytes, base: int) -> ProtectedTable:
    """Require one complete 15-entry table with a shared Thumb handler."""
    signature = PROTECTED_IDS[0].to_bytes(2, 'big') + b'\0\0'
    matches = []
    start = 0
    while (offset := image.find(signature, start)) != -1:
        start = offset + 1
        if offset + 16 * len(PROTECTED_IDS) > len(image):
            continue
        entries = {}
        handlers = set()
        for index, seem in enumerate(PROTECTED_IDS):
            pos = offset + index * 16
            record = image[pos:pos + 16]
            if record[:4] != seem.to_bytes(2, 'big') + b'\0\0' or record[8:] != b'\0' * 8:
                break
            entries[seem] = base + pos
            handlers.add(int.from_bytes(record[4:8], 'big'))
        else:
            if len(handlers) == 1:
                handler = handlers.pop()
                if handler & 1 and base <= handler - 1 < base + len(image):
                    matches.append(ProtectedTable(base + offset, handler, entries))
    if len(matches) != 1:
        raise ValueError(f'expected one complete protected table, found {len(matches)}')
    return matches[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dump', type=Path, help='read-only A0000000 NOR dump')
    args = parser.parse_args()
    image = args.dump.read_bytes()
    base = 0xA0000000
    table = locate_protected_table(image, base)
    print(f'SHA-256: {hashlib.sha256(image).hexdigest()}')
    print(f'protected table: {table.address:08X}')
    print(f'shared Thumb handler: {table.handler:08X}')
    for seem in SUBSIDY_IDS:
        print(f'SEEM {seem:04X}: record at {table.entries[seem]:08X}')
    print('No changes were made. Handler behavior and flash-write safety are unverified.')


if __name__ == '__main__':
    main()
