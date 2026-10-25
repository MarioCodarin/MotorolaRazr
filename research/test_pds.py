import unittest
from pathlib import Path

from pds import (
    parse_pds, active_checksum, ident_text, latest_ident, latest_payload,
    p2k_relation, replace_latest_payload,
)

DUMP = Path(__file__).resolve().parents[1] / 'diagnostics' / 'nor_a000.bin'
SEEMS = DUMP.parent


class PdsTests(unittest.TestCase):
    def test_records_and_checksum(self):
        data = (
            b'PDS_3022\xff\xf9'
            + bytes.fromhex('000afff9000402069892')
            + bytes.fromhex('029efff900026567')
            + b'\xff' * 12
        )
        area = parse_pds(data)
        self.assertEqual(area.status, 0xFFF9)
        self.assertEqual([r.seem for r in area.records], [0x000A, 0x029E])
        self.assertEqual(area.records[0].payload, bytes.fromhex('02069892'))
        self.assertEqual(active_checksum(area), 0x6567)
        self.assertTrue(area.checksum_valid)

    def test_rejects_invalid_status_and_truncation(self):
        for tail in (bytes.fromhex('000a00010002abcd'),
                     bytes.fromhex('000afff90004abcd')):
            with self.assertRaises(ValueError):
                parse_pds(b'PDS_3022\xff\xf9' + tail)

    def test_inactive_records_excluded(self):
        data = (
            b'PDS_3022\xff\xf9'
            + bytes.fromhex('000afff0000400010002')
            + bytes.fromhex('000afffa000400030004')
            + bytes.fromhex('029efff90002fff8')
            + b'\xff' * 6
        )
        area = parse_pds(data)
        self.assertEqual(active_checksum(area), 0xFFF8)
        self.assertTrue(area.checksum_valid)


class IdentAndP2kTests(unittest.TestCase):
    def test_ident_text_strips_prefix_and_padding(self):
        payload = b'@(#)USIZRGBLH3GITR26111058' + b'\0' * 8
        self.assertEqual(ident_text(payload), 'USIZRGBLH3GITR26111058')
        self.assertIsNone(ident_text(b'\x11\x92' + b'\0' * 6))

    def test_latest_ident_prefers_later_active_record(self):
        data = (
            b'PDS_3022\xff\xf9'
            + bytes.fromhex('02cafff9000c') + b'@(#)OLDFLEX\x00'
            + bytes.fromhex('02cafff90010') + b'@(#)Brandingfree'
            + bytes.fromhex('029efff90002ffff')
            + b'\xff' * 8
        )
        area = parse_pds(data)
        self.assertEqual(latest_ident(area, 0x02CA), 'Brandingfree')

    def test_p2k_relation_detects_runtime_transform(self):
        pds_payload = bytes(range(40))
        p2k = b'\x00\x00\x00\x08' + b'\xff' * 28
        nor = b'HEAD' + pds_payload + b'TAIL'
        rel = p2k_relation(pds_payload, p2k, nor)
        self.assertEqual(rel['pds_len'], 40)
        self.assertEqual(rel['p2k_len'], 32)
        self.assertFalse(rel['embedded'])
        self.assertFalse(rel['in_nor'])
        self.assertTrue(p2k_relation(pds_payload, pds_payload[:8], nor)['embedded'])


@unittest.skipUnless(DUMP.is_file(), 'NOR dump is not present')
class DumpTests(unittest.TestCase):
    def test_active_brandingfree_and_inactive_h3g_ident(self):
        image = DUMP.read_bytes()
        active = parse_pds(image[0x40000:0x60000])
        inactive = parse_pds(image[0x60000:0x80000])
        self.assertEqual(latest_ident(active, 0x02CA), 'R26111LD_U_96.A0.0ER')
        self.assertEqual(latest_ident(active, 0x02CB), 'Brandingfree')
        self.assertEqual(latest_ident(inactive, 0x02CB), 'USIZRGBLH3GITR26111058')
        self.assertTrue(active.checksum_valid)

    def test_subsidy_p2k_bytes_are_absent_from_nor(self):
        image = DUMP.read_bytes()
        active = parse_pds(image[0x40000:0x60000])
        expected = {
            0x015C: (32, 0, False, False),
            0x015D: (32, 0, False, False),
            0x01C3: (40, 32, False, False),
            0x01C4: (40, 32, False, False),
        }
        for seem, (pds_len, p2k_len, embedded, in_nor) in expected.items():
            p2k_path = SEEMS / f'{seem:04x}_0001.seem'
            p2k = p2k_path.read_bytes() if p2k_path.is_file() else b''
            rel = p2k_relation(latest_payload(active, seem), p2k, image)
            self.assertEqual(
                (rel['pds_len'], rel['p2k_len'], rel['embedded'], rel['in_nor']),
                (pds_len, p2k_len, embedded, in_nor),
                msg=hex(seem),
            )

    def test_replace_latest_payload_refreshes_checksum(self):
        image = DUMP.read_bytes()
        block = bytearray(image[0x40000:0x60000])
        original = parse_pds(block)
        old = latest_payload(original, 0x015C)
        self.assertEqual(len(old), 32)
        marker = bytes((i * 7 + 3) & 0xFF for i in range(32))
        patched = replace_latest_payload(bytes(block), 0x015C, marker)
        area = parse_pds(patched)
        self.assertTrue(area.checksum_valid)
        self.assertEqual(latest_payload(area, 0x015C), marker)
        self.assertEqual(latest_ident(area, 0x02CB), latest_ident(original, 0x02CB))
        self.assertNotEqual(latest_payload(area, 0x02C9), latest_payload(original, 0x02C9))

    def test_patched_pds_image_checksum_and_015c_matches_015d(self):
        path = DUMP.parent / 'pds_patched.bin'
        if not path.is_file():
            self.skipTest('patched PDS image not built yet')
        data = path.read_bytes()
        area = parse_pds(data)
        self.assertTrue(area.checksum_valid)
        c = latest_payload(area, 0x015C)
        d = latest_payload(area, 0x015D)
        self.assertEqual(len(c), 32)
        self.assertEqual(c, d)
        orig = parse_pds(DUMP.read_bytes()[0x40000:0x60000])
        self.assertNotEqual(c, latest_payload(orig, 0x015C))
        self.assertEqual(latest_ident(area, 0x02CB), latest_ident(orig, 0x02CB))


if __name__ == '__main__':
    unittest.main()
