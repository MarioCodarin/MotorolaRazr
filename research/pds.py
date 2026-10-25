"""Inspect Motorola PDS_3022 records in an existing NOR backup, read only.

The CLI prints record identifiers, sizes, and @(#) ident strings from
SEEM 02CA/02CB. It never prints subsidy-record payloads.
"""

from dataclasses import dataclass
from pathlib import Path
import argparse


STATUSES = {0xFFF0, 0xFFF9, 0xFFFA}
ACTIVE_STATUSES = {0xFFF9, 0xFFFA}
TARGET_IDS = {0x015C, 0x015D, 0x01C3, 0x01C4}
IDENT_IDS = (0x02CA, 0x02CB)
PDS_OFFSETS = (0x40000, 0x60000)
PDS_SIZE = 0x20000


@dataclass(frozen=True)
class Record:
    seem: int
    status: int
    offset: int
    payload: bytes


@dataclass(frozen=True)
class PDS:
    version: bytes
    status: int
    records: tuple[Record, ...]
    end_offset: int

    @property
    def checksum_valid(self) -> bool:
        checks = [r for r in self.records if r.seem == 0x029E and r.status in ACTIVE_STATUSES]
        if not checks:
            checks = [r for r in self.records if r.seem == 0x02C9 and r.status in ACTIVE_STATUSES]
        return len(checks) == 1 and len(checks[0].payload) == 2 and int.from_bytes(checks[0].payload, 'big') == active_checksum(self)


def parse_pds(data: bytes) -> PDS:
    if len(data) < 10 or not data[:8].startswith(b'PDS_'):
        raise ValueError('missing PDS header')
    status = int.from_bytes(data[8:10], 'big')
    if status not in STATUSES:
        raise ValueError('invalid PDS status')
    records = []
    pos = 10
    while pos < len(data):
        if data[pos:] == b'\xff' * (len(data) - pos):
            break
        if pos + 6 > len(data):
            raise ValueError(f'truncated record header at {pos:#x}')
        seem = int.from_bytes(data[pos:pos+2], 'big')
        marker = int.from_bytes(data[pos+2:pos+4], 'big')
        size = int.from_bytes(data[pos+4:pos+6], 'big')
        if marker not in STATUSES:
            raise ValueError(f'invalid record status at {pos:#x}')
        if pos + 6 + size > len(data):
            raise ValueError(f'truncated record payload at {pos:#x}')
        records.append(Record(seem, marker, pos, data[pos+6:pos+6+size]))
        pos += 6 + size
    return PDS(data[:8], status, tuple(records), pos)


def active_checksum(area: PDS) -> int:
    """Legacy PDS checksum over 16-bit words in active records only."""
    total = 0
    for record in area.records:
        if record.status not in ACTIVE_STATUSES or record.seem in (0x029E, 0x02C9):
            continue
        payload = record.payload
        if len(payload) % 2:
            raise ValueError(f'odd payload length in {record.seem:04X}')
        total += sum(int.from_bytes(payload[i:i+2], 'big') for i in range(0, len(payload), 2))
    return (0xFFFF - total) & 0xFFFF


def ident_text(payload: bytes) -> str | None:
    """Return the ASCII ident after @(#), if this is a version/flex record."""
    if not payload.startswith(b'@(#)'):
        return None
    return payload[4:].split(b'\0', 1)[0].decode('ascii', 'replace')


def latest_ident(area: PDS, seem: int) -> str | None:
    for record in reversed(area.records):
        if record.seem == seem and record.status in ACTIVE_STATUSES:
            return ident_text(record.payload)
    return None


def latest_payload(area: PDS, seem: int) -> bytes | None:
    for record in reversed(area.records):
        if record.seem == seem and record.status in ACTIVE_STATUSES:
            return record.payload
    return None


def latest_record(area: PDS, seem: int) -> Record | None:
    for record in reversed(area.records):
        if record.seem == seem and record.status in ACTIVE_STATUSES:
            return record
    return None


def apply_checksum(data: bytes) -> bytes:
    """Write the legacy checksum into the latest active 02C9/029E record."""
    area = parse_pds(data)
    rec = latest_record(area, 0x02C9) or latest_record(area, 0x029E)
    if rec is None or len(rec.payload) != 2:
        raise ValueError('no checksum record')
    out = bytearray(data)
    out[rec.offset + 6:rec.offset + 8] = active_checksum(area).to_bytes(2, 'big')
    return bytes(out)


def replace_latest_payload(data: bytes, seem: int, payload: bytes) -> bytes:
    """Replace one active record's payload in a PDS block and refresh checksum."""
    area = parse_pds(data)
    rec = latest_record(area, seem)
    if rec is None:
        raise ValueError(f'no active SEEM {seem:04X}')
    if len(payload) != len(rec.payload):
        raise ValueError(
            f'SEEM {seem:04X} payload {len(payload)} != stored {len(rec.payload)}'
        )
    out = bytearray(data)
    out[rec.offset + 6:rec.offset + 6 + len(payload)] = payload
    return apply_checksum(bytes(out))


def p2k_relation(pds_payload: bytes | None, p2k: bytes, nor: bytes) -> dict:
    """Structural comparison only; callers must not print payloads."""
    embedded = bool(p2k) and pds_payload is not None and p2k in pds_payload
    return {
        'pds_len': None if pds_payload is None else len(pds_payload),
        'p2k_len': len(p2k),
        'embedded': embedded,
        'in_nor': bool(p2k) and p2k in nor,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dump', type=Path, help='existing A0000000 NOR backup')
    parser.add_argument('--seems', type=Path, help='directory of P2K SEEM copies')
    args = parser.parse_args()
    image = args.dump.read_bytes()
    if len(image) < max(PDS_OFFSETS) + PDS_SIZE:
        parser.error('NOR backup is too short for both PDS regions')
    for base in PDS_OFFSETS:
        area = parse_pds(image[base:base+PDS_SIZE])
        print(f'PDS at A0000000+{base:05X}: {area.version.decode("ascii")}, '
              f'status={area.status:04X}, records={len(area.records)}, '
              f'checksum={"valid" if area.checksum_valid else "unverified"}')
        for seem in IDENT_IDS:
            ident = latest_ident(area, seem)
            if ident is not None:
                print(f'  SEEM {seem:04X} ident: {ident}')
        for record in area.records:
            if record.seem in TARGET_IDS:
                print(f'  SEEM {record.seem:04X}: status={record.status:04X}, '
                      f'length={len(record.payload)}, offset={record.offset:05X}')
    if args.seems:
        active = parse_pds(image[PDS_OFFSETS[0]:PDS_OFFSETS[0]+PDS_SIZE])
        print('P2K comparison (sizes and presence only):')
        for seem in sorted(TARGET_IDS):
            seem_path = args.seems / f'{seem:04x}_0001.seem'
            p2k = seem_path.read_bytes() if seem_path.is_file() else b''
            rel = p2k_relation(latest_payload(active, seem), p2k, image)
            print(f'  SEEM {seem:04X}: PDS_len={rel["pds_len"]}, P2K_len={rel["p2k_len"]}, '
                  f'embedded={rel["embedded"]}, in_NOR={rel["in_nor"]}')
    print('Read only; no unlock or flash write performed.')


if __name__ == '__main__':
    main()
