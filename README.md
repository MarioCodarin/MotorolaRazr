# Motorola RAZR V3xx subsidy unlock

A retail V3xx on firmware `R26111LD_U_96.A0.0ER`, boot `03.02`, lost the subsidy prompt after one Thumb halfword in the code sector changed from `d0 07` to `e0 07`. It came back as USB `22b8:6402`. `AT+CREG?` returned `+CREG: 0,1`.

The script refuses any other code sector. This is not a method for the V3, V3i, or V3x, and it is not a SEEM edit.

## Do this

1. [Install the two tools and the Python packages](docs/guide.md#1-install).
2. Enter flash mode (`22b8:6403`) and [dump the first 32 MiB of NOR](docs/guide.md#2-dump).
3. Check the dump. This sends no USB traffic:

   ```sh
   python3 research/patch_subsidy_sector.py
   ```

4. Enter flash mode again, then write:

   ```sh
   python3 research/patch_subsidy_sector.py --write
   ```

5. The subsidy prompt should be gone. The script does not query the network. On the tested phone, `AT+CREG?` returned `+CREG: 0,1`.

To undo the write, enter flash mode and run:

```sh
python3 research/patch_subsidy_sector.py --restore
```

## Do not

- Do not edit SEEMs `015C`, `015D`, `01C3`, or `01C4`. Those trials stayed locked or bootlooped. [What did not unlock it](docs/what-did-not-work.md).
- Do not send `AT+MODE=24`. From `22b8:6402` that enumerates mass storage `22b8:6410`, not the bootloader.
- Do not send a third `ERASE`. Two selects buffer programming. A third selects erase without a write.
- Do not guess subsidy codes.
- Do not commit `diagnostics/`. The dump contains personal data.

## The byte

| Item | Value |
| --- | --- |
| USB normal / P2K / flash | `22b8:6402` / `22b8:6401` / `22b8:6403` |
| Sector | flash `0xA0840000`, 128 KiB. The first `BIN` erases the whole sector. |
| File offset | `0x855D70` |
| Change | `d0 07` to `e0 07` (`beq.n` to `b.n`) |
| Original sector SHA-256 | `cbe48aae37439587731673f4d95a9d20d5b7e2e50f8b7a409ce068f2ae35e7a5` |
| Patched sector SHA-256 | `a0f028d3069d76d7d0fc89d102d7dd30e08a226e2bfc56164407ff54a84482b9` |

The full NOR digest differs per phone. The check above is the code sector. Detail is in [docs/guide.md](docs/guide.md). The lab journal is [research/README.md](research/README.md).
