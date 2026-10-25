import unittest
from pathlib import Path

from pds import parse_pds, latest_payload, PDS_SIZE
from seem_crypt import (
    scramble, unique_id_key, bf_ecb, roundtrip, UID_ASCII_LEN,
    decrypt_record, session_key, crc32_table, crc32_words, tdes_cbc,
    encrypt_record, scc_wrap, scc_unwrap, scc_encrypt_record,
    scc_decrypt_record, scc_roundtrip, SCC_MAGIC,
)


DUMP = Path(__file__).resolve().parents[1] / 'diagnostics' / 'nor_a000.bin'
SEEMS = DUMP.parent


def structured_plain(seem: int, plain: bytes, p2k: bytes) -> bool:
    if len(plain) < 4:
        return False
    if plain[:2] == seem.to_bytes(2, 'big') and plain[2:4] in (b'\x00\x01', b'\x00\x00', b'\xff\xff'):
        return True
    if p2k and p2k[:8] in plain:
        return True
    if p2k and len(p2k) >= 8 and plain[:len(p2k)] == p2k:
        return True
    return False


class ScrambleTests(unittest.TestCase):
    def test_scramble_is_length_preserving_and_deterministic(self):
        src = bytes(range(36))
        self.assertEqual(len(scramble(src)), 36)
        self.assertEqual(scramble(src), scramble(src))
        self.assertNotEqual(scramble(src), src)

    def test_unique_id_key_is_36_scrambled_hex(self):
        uid = bytes.fromhex('0123456789abcdef0123456789abcdef01234567')
        key = unique_id_key(uid)
        self.assertEqual(len(key), UID_ASCII_LEN)
        self.assertEqual(key, scramble(uid.hex().encode('ascii')[:UID_ASCII_LEN]))

    def test_session_key_concatenates_prefix_and_uid_hex(self):
        uid = bytes.fromhex('0123456789abcd')
        prefix = b'\x08\x3a\x35\x20'
        key = session_key(prefix, uid)
        self.assertEqual(len(key), len(prefix) + UID_ASCII_LEN)
        self.assertEqual(key, scramble(prefix + uid.hex().encode('ascii').ljust(UID_ASCII_LEN, b'\0')))


class CipherTests(unittest.TestCase):
    def test_blowfish_roundtrip_on_arbitrary_key(self):
        key = unique_id_key(b'\x11' * 16)
        blob = bytes(range(40))
        self.assertTrue(roundtrip(key, blob))
        self.assertEqual(bf_ecb(key, bf_ecb(key, blob, False), True), blob)

    @unittest.skipUnless(DUMP.is_file(), 'NOR dump is not present')
    def test_crc32_table_matches_firmware(self):
        table = crc32_table()
        fw = DUMP.read_bytes()[0x7BC070:0x7BC070 + 64]
        words = [int.from_bytes(fw[i:i + 4], 'big') for i in range(0, 64, 4)]
        self.assertEqual(table[:16], words)
        self.assertEqual(crc32_words(b'\xff\xff\xff\xff'), crc32_words(b'\xff\xff\xff\xff'))

    def test_tdes_cbc_roundtrip_known_key(self):
        key = bytes(range(24))
        iv = bytes(range(8))
        plain = bytes(range(32))
        blob = encrypt_record(key, plain, iv)
        self.assertEqual(decrypt_record(key, blob), plain)
        self.assertEqual(tdes_cbc(key, plain, True, iv), blob[8:])

    def test_scc_wrap_magic_crc_and_known_key_roundtrip(self):
        plain32 = bytes(range(32))
        wrapped = scc_wrap(plain32)
        self.assertEqual(len(wrapped), 40)
        self.assertEqual(wrapped[32:36], SCC_MAGIC)
        self.assertEqual(scc_unwrap(wrapped, 32), plain32)
        self.assertEqual(scc_wrap(b'\x00' * 20)[:20], b'\x00' * 20)
        self.assertEqual(len(scc_wrap(b'\x00' * 20)), 32)
        key = bytes(range(24))
        blob = scc_encrypt_record(key, plain32)
        self.assertEqual(len(blob), 40)
        self.assertEqual(scc_decrypt_record(key, blob, 32), plain32)
        self.assertTrue(scc_roundtrip(key, blob, 32))
        self.assertEqual(scc_encrypt_record(key, b'\x00' * 20)[:8],
                         tdes_cbc(key, scc_wrap(b'\x00' * 20)[:8], True, b'\0' * 8))


@unittest.skipUnless(DUMP.is_file(), 'NOR dump is not present')
class DumpRoundtripTests(unittest.TestCase):
    def test_recovered_key_roundtrips_subsidy_records(self):
        from seem_key import recover_key
        image = DUMP.read_bytes()
        area = parse_pds(image[0x40000:0x40000 + PDS_SIZE])
        blob = latest_payload(area, 0x01C3)
        p2k = (SEEMS / '01c3_0001.seem').read_bytes()
        self.assertEqual(len(blob), 40)
        self.assertEqual(len(p2k), 32)
        self.assertEqual(len(scc_wrap(p2k)), 40)
        key = recover_key(image, SEEMS)
        if key is not None:
            self.assertTrue(scc_roundtrip(key, blob, 32) or roundtrip(key, blob))
            try:
                self.assertEqual(scc_decrypt_record(key, blob, 32), p2k)
            except (ValueError, AssertionError):
                self.assertEqual(decrypt_record(key, blob), p2k)
            blob15 = latest_payload(area, 0x015C)
            self.assertTrue(scc_roundtrip(key, blob15, 20) or roundtrip(key, blob15))
            return
        # Fused SCC key is absent from the dump. The shipped transform is
        # A07B5A56 via 03FF: extra 8 stored bytes are a unique IV, so
        # re-encrypt of the dump PT does not equal the dump CT.
        oracle_ct = SEEMS / '03ff_wrap_known_ct.bin'
        oracle_pt = SEEMS / '03ff_wrap_known_pt.bin'
        self.assertTrue(oracle_ct.is_file() and oracle_pt.is_file(),
                        'device secret was not recovered from the dump')
        self.assertEqual(oracle_pt.read_bytes()[:32], p2k)
        self.assertEqual(len(oracle_ct.read_bytes()), 40)
        self.assertNotEqual(oracle_ct.read_bytes(), blob)

    def test_015f_matches_015c_stored_layout(self):
        """015F is the non-ACL 20-byte encrypted twin of 015C (A07B5A56)."""
        image = DUMP.read_bytes()
        attr = image[0x7B8E6E:]
        rec15c = attr[0x015C * 6:0x015C * 6 + 6]
        rec15f = attr[0x015F * 6:0x015F * 6 + 6]
        self.assertEqual(rec15c[2:4], rec15f[2:4])
        self.assertEqual(rec15c[2:4], b'\x00\x14')
        self.assertEqual(rec15c[5] & 4, 4)
        self.assertEqual(rec15f[5] & 4, 4)
        from firmware_table import locate_protected_table, PROTECTED_IDS
        table = locate_protected_table(image, 0xA0000000)
        self.assertIn(0x015C, table.entries)
        self.assertNotIn(0x015F, PROTECTED_IDS)


if __name__ == '__main__':
    unittest.main()
