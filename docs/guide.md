# Procedure

Tested on one retail Motorola RAZR V3xx: firmware `R26111LD_U_96.A0.0ER`, boot `03.02`, ArgonLV, AMD/Spansion NOR. The offline check refuses a dump whose 128 KiB sector at file `0x840000` is not SHA-256 `cbe48aae37439587731673f4d95a9d20d5b7e2e50f8b7a409ce068f2ae35e7a5`.

What was tried and did not clear the lock is in [what-did-not-work.md](what-did-not-work.md).

The first `BIN` aimed at `0xA0840000` erases that entire 128 KiB sector, then programs it 32 bytes at a time. The script reads the live sector before any `ERASE`. It sends `ERASE` twice and never a third time. It does not modify `diagnostics/nor_a000.bin`.

## 1. Install

Leave the phone tools as local checkouts. This repo does not vendor them.

| Tool | Pin | Role |
| --- | --- | --- |
| [EXL/FlashTerminal](https://github.com/EXL/FlashTerminal) `master` | `8ae1de7` | Dump NOR. MIT. |
| [MotoFanRu/Hitagi](https://github.com/MotoFanRu/Hitagi) branch `argon` | `d6ebbec` | Program the sector. MIT. |

p2kc is not used. `research/patches/p2kc-macos-usb-handle.patch` is only a macOS compile fix from the earlier SEEM reads.

```sh
git clone https://github.com/EXL/FlashTerminal.git tools/FlashTerminal
git -C tools/FlashTerminal checkout 8ae1de7af6bc342dfa204675a3428ca9266972c2

git clone -b argon https://github.com/MotoFanRu/Hitagi.git tools/Hitagi
git -C tools/Hitagi checkout d6ebbeca0d2712bf76e85f69721c018ec4b72b5a
git -C tools/Hitagi apply ../../research/patches/hitagi-scc.patch
make -C tools/Hitagi PLATFORM=ARGONLV FLASH_TYPE=amd16

python3 -m pip install -r requirements.txt
```

The build needs `arm-none-eabi-gcc` and writes `tools/Hitagi/hitagi.bin`. That is the loader the patch script uploads. Apply `research/patches/hitagi-scc.patch` before `make`. The tested loader included it. The sector write does not send the `SCCRUN` command the patch adds.

`requirements.txt` is `pyusb`, `pyserial`, and `pycryptodome`. The patch script needs `pyusb`. The crypt tests need `pycryptodome`.

## 2. Dump

Flash mode is USB product `0x6403` (`22b8:6403`). This repo does not record which keys were held on the tested handset. The [LPC wiki Motorola dump page](https://lpcwiki.miraheze.org/wiki/Dumping_firmware_from_phones/Motorola) says the usual bootloader hold is `*` and `#`, then plug the cable in. It names other keys only for the WX430 and Q11. Success is the product id, not the legend on the keys:

```sh
python3 -c "import usb.core; d=usb.core.find(idVendor=0x22b8); print('absent' if d is None else hex(d.idProduct))"
```

`0x6402` is normal mode, `0x6401` is P2K, `0x6403` is flash mode, `0x6410` is mass storage. `AT+MODE=24` from `0x6402` produces `0x6410`. Do not pass FlashTerminal `-s`. Unplug, power off, and use the key hold again.

In `tools/FlashTerminal/FlashTerminal.py`, function `worksheet`:

1. Delete the leading `#` on the line that uploads `loaders/K3_RAMDLD_0320.ldr`. That line is inside `if '-l'`.
2. Delete the leading `#` on the K3 dump line and set the end and the step as below. Leave every other loader and dump commented out. Do not enable `K3_ROM_Dump_2`.

```python
mfp_upload_binary_to_addr(er, ew, 'loaders/K3_RAMDLD_0320.ldr', 0x80000000, 0x80000038, True)
mfp_dump_read(er, ew, 'K3_ROM_Dump_1.bin', 0xA0000000, 0xA2000000, 0x200)
```

`mfp_dump_read` writes whole steps only, while `address + step` is still `<= end`. Step `0x300` does not divide 32 MiB. Both stock ends, `0xA1FFFFFF` in Worksheet.md and `0xA2000000` in the commented `.py` line, stop 512 bytes early at 33,553,920 bytes. The checker requires 33,554,432 bytes. Step `0x200` and end `0xA2000000` land on that size.

From `tools/FlashTerminal`, with the phone already `22b8:6403`:

```sh
python3 FlashTerminal.py -l
```

`-l` runs the upload. Without `-l`, an uncommented dump still runs, and K3 is not loaded. The two lines do nothing while the `#` remains.

Copy `tools/FlashTerminal/K3_ROM_Dump_1.bin` to `diagnostics/nor_a000.bin` and `chmod 600` it. Stop if the size is not 33554432.

Power-cycle back into `6403` before the write. Do not upload Hitagi while K3 is still running at `0x80000038`. That upload timed out, and the phone restarted with NOR unchanged.

## 3. Check

No USB:

```sh
python3 research/patch_subsidy_sector.py
```

It stops unless the file is 33,554,432 bytes, contains `R26111LD_U_96.A0.0ER`, still has `d0 07` at file `0x855D70`, and the sector hash matches. It prints the full-image SHA-256 as information. That digest is per handset. A file that is 512 bytes short names the `0x300` step in the error.

## 4. Write

Hold flash mode until USB shows `22b8:6403`, then:

```sh
python3 research/patch_subsidy_sector.py --write
```

The script reads the live sector first. It sends no `ERASE` when that sector is already the patched image, and it stops with no `ERASE` when the live sector is neither the backup nor the patched image. After two `ERASE` commands and the `BIN` stream it reads the sector back. The tested phone matched `e0 07` and the patched sector hash. `RESTART` dropped it off the bus. It later enumerated as `22b8:6402`.

The script does not send `AT+CREG?`.

The on-disk dump stays the original sector. To put the halfword back, enter `22b8:6403` and run:

```sh
python3 research/patch_subsidy_sector.py --restore
```

If a `BIN` fails after the erase, the script rewrites the sector it read before the erase and does not send another `ERASE`. It also saves that pre-erase sector as `diagnostics/sector_a0840000_before.bin`. `--write` and `--restore` will not program a half-written sector. If the process dies after the erase, enter `6403` and run:

```sh
python3 research/patch_subsidy_sector.py --replay-saved
```

That command programs the saved file only when the file is the original sector or the patched sector. It does not replace the saved file with the broken live read.

## 5. Tests

```sh
python3 -m unittest discover -s research -p 'test_*.py'
```

The patch test builds a synthetic sector and does not need a phone or a dump. Tests that read `diagnostics/nor_a000.bin` skip when the file is absent.
