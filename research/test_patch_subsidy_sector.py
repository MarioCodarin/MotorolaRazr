import unittest

from patch_subsidy_sector import PATCH_INDEX, SECTOR_SIZE, build_patch


class BuildPatchTests(unittest.TestCase):
    def test_build_patch_changes_only_the_branch_byte(self):
        sector = bytearray(b'\x00' * SECTOR_SIZE)
        sector[PATCH_INDEX:PATCH_INDEX + 2] = b'\xd0\x07'
        patched = build_patch(bytes(sector))
        self.assertEqual(patched[PATCH_INDEX:PATCH_INDEX + 2], b'\xe0\x07')
        diffs = [i for i, (a, b) in enumerate(zip(sector, patched)) if a != b]
        self.assertEqual(diffs, [PATCH_INDEX])

    def test_build_patch_rejects_a_different_halfword(self):
        sector = bytearray(b'\x00' * SECTOR_SIZE)
        sector[PATCH_INDEX:PATCH_INDEX + 2] = b'\xd1\x07'
        with self.assertRaises(SystemExit):
            build_patch(bytes(sector))


if __name__ == '__main__':
    unittest.main()
