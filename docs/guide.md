# Procedure

Tested on one retail Motorola RAZR V3xx. Firmware ident `R26111LD_U_96.A0.0ER`, boot `03.02`, ArgonLV, 64 MiB AMD/Spansion NOR. The writer refuses a dump whose code sector at file `0x840000` is not SHA-256 `cbe48aae37439587731673f4d95a9d20d5b7e2e50f8b7a409ce068f2ae35e7a5`, or whose halfword at file `0x855D70` is not `d0 07`.

This is not a method for the V3, V3i, or V3x. It is not a SEEM edit. The negative results are in [what-did-not-work.md](what-did-not-work.md).

The first `BIN` aimed at `0xA0840000` erases that entire 128 KiB sector, then programs it 32 bytes at a time. The script reads the live sector first and does not send `ERASE` when the live sector is already the requested image. It sends `ERASE` twice and never a third time. It does not modify `diagnostics/nor_a000.bin`.

## Tools

Leave these as local checkouts. This repo does not vendor them.

| Tool | Pin | Role |
| --- | --- | --- |
| [EXL/FlashTerminal](https://github.com/EXL/FlashTerminal) `master` | `8ae1de7` | USB framing, K3 dump. MIT. |
| [MotoFanRu/Hitagi](https://github.com/MotoFanRu/Hitagi) branch `argon` | `d6ebbec` | RAM loader that can program AMD NOR. MIT. |
| [pulkomandy/p2kc](https://github.com/pulkomandy/p2kc) `master` | `3aa4747` | Earlier SEEM reads only. GPL-2. Not used by the patch. |

```sh
git clone https://github.com/EXL/FlashTerminal.git tools/FlashTerminal
git -C tools/FlashTerminal checkout 8ae1de7af6bc342dfa204675a3428ca9266972c2

git clone -b argon https://github.com/MotoFanRu/Hitagi.git tools/Hitagi
git -C tools/Hitagi checkout d6ebbeca0d2712bf76e85f69721c018ec4b72b5a
make -C tools/Hitagi PLATFORM=ARGONLV FLASH_TYPE=amd16
```

The build needs `arm-none-eabi-gcc` and writes `tools/Hitagi/hitagi.bin`. That is the loader `research/patch_subsidy_sector.py` uploads.

`research/patches/hitagi-scc.patch` adds an `SCCRUN` command. That command was not sent during the sector write. The patch above does not apply it. `research/patches/p2kc-macos-usb-handle.patch` is a macOS compile fix for p2kc and is not part of the unlock.

```sh
python3 -m pip install -r requirements.txt
```

`requirements.txt` is `pyusb`, `pyserial`, and `pycryptodome`. The patch script needs the first. The crypt tests need the third.

## Dump

Flash mode on this handset is the key hold that enumerates USB `22b8:6403`. The [LPC wiki Motorola dump page](https://lpcwiki.miraheze.org/wiki/Dumping_firmware_from_phones/Motorola) says the usual bootloader hold is `*` and `#` while the cable is plugged in, and names other keys only for the WX430 and Q11. Confirm the product id before any dump or write. `AT+MODE=24` from `22b8:6402` enumerates mass storage `22b8:6410`, not the bootloader.

FlashTerminal's ReadMe lists the V3xx on `K3_RAMDLD_0320.ldr`. Its KRZR K3 worksheet block is the map this phone used. From a fresh `6403` session, the two calls are:

```python
mfp_upload_binary_to_addr(er, ew, 'loaders/K3_RAMDLD_0320.ldr', 0x80000000, 0x80000038, True)
mfp_dump_read(er, ew, 'K3_ROM_Dump_1.bin', 0xA0000000, 0xA1FFFFFF, 0x300)
```

Copy that 33,554,432-byte file to `diagnostics/nor_a000.bin` and `chmod 600` it. The worksheet's second read, `B4000000–B5FFFFFF`, is a user-data region on this phone. Keep it local. The patch does not read it.

Do not upload Hitagi while the K3 loader is still running at `0x80000038`. Power-cycle back into `6403` before the write. A Hitagi upload into a session that was already running K3 timed out, and the phone restarted with NOR unchanged.

## Check, write, restore

Offline check, no USB:

```sh
python3 research/patch_subsidy_sector.py
```

It stops, without USB traffic, unless the file is 32 MiB, contains `R26111LD_U_96.A0.0ER`, still has `d0 07` at file `0x855D70`, and the 128 KiB sector hashes to the original value above. It prints the full-image SHA-256 as information. That digest is per handset.

Hold flash mode until USB shows `22b8:6403`, then:

```sh
python3 research/patch_subsidy_sector.py --write
```

The script reads the live sector before any `ERASE`. It refuses, and sends no `ERASE`, if that sector is neither the backup nor the already-patched image. After two `ERASE` commands and the `BIN` stream it reads the sector back. The tested phone matched `e0 07` and the patched sector hash, then `RESTART` dropped it off the bus. It later enumerated as `22b8:6402`.

The script does not send `AT+CREG?`. On the tested phone that command returned `+CREG: 0,1`, and the owner confirmed the subsidy prompt was gone.

The on-disk dump stays the original sector. To put the halfword back, enter `22b8:6403` again and run:

```sh
python3 research/patch_subsidy_sector.py --restore
```

If a `BIN` fails after the erase, the script rewrites the sector it saved from the live read and does not send another `ERASE`. If that rollback also fails, the next `6403` session has to finish the sector before any other edit. The saved copy is `diagnostics/sector_a0840000_before.bin`, which is gitignored with the rest of `diagnostics/` except this directory's notes.

## Tests

```sh
python3 -m unittest discover -s research -p 'test_*.py'
```

The patch test builds a synthetic sector and does not need a phone or a dump. Tests that read `diagnostics/nor_a000.bin` skip when the file is absent.
