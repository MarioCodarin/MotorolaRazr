import unittest

from firmware_table import locate_protected_table


class FirmwareTableTests(unittest.TestCase):
    def test_finds_protected_entries_at_checked_offsets(self):
        ids = (0x015E, 0x015B, 0x005F, 0x015D, 0x015C, 0x0161,
               0x0189, 0x01C3, 0x01C4, 0x01C5, 0x01C6, 0x01C7,
               0x01F8, 0x01F9, 0x01FA)
        base = 0xA0000000
        table_address = base + 0x40
        handler = base + 0x21
        records = b''.join(
            seem.to_bytes(2, 'big') + b'\0\0' + handler.to_bytes(4, 'big') + b'\0' * 8
            for seem in ids
        )
        image = b'X' * 0x40 + records + b'Y' * 0x20

        table = locate_protected_table(image, base)

        self.assertEqual(table.address, table_address)
        self.assertEqual(table.handler, handler)
        self.assertEqual(table.entries[0x015C], table_address + 4 * 16)
        self.assertEqual(table.entries[0x01C4], table_address + 8 * 16)

    def test_rejects_table_with_mixed_handlers(self):
        ids = (0x015E, 0x015B, 0x005F, 0x015D, 0x015C, 0x0161,
               0x0189, 0x01C3, 0x01C4, 0x01C5, 0x01C6, 0x01C7,
               0x01F8, 0x01F9, 0x01FA)
        records = b''.join(
            seem.to_bytes(2, 'big') + b'\0\0' +
            (0xA0000021 if seem != 0x015D else 0xA0000041).to_bytes(4, 'big') +
            b'\0' * 8 for seem in ids
        )
        with self.assertRaises(ValueError):
            locate_protected_table(records, 0xA0000000)


if __name__ == '__main__':
    unittest.main()
