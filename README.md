# Motorola RAZR V3xx subsidy unlock

On 25 October 2026 a retail RAZR V3xx, firmware `R26111LD_U_96.A0.0ER`, boot `03.02`, booted with the subsidy check forced inactive. The change is one Thumb halfword inside signed code. `SubsidyLockDispatch` at `0xA0855D58` treats element `0x9BD` values `0x00`, `0x11`, and `0xFF` as inactive. The first of those compares is `beq.n` at `0xA0855D70` (`d0 07`). Replacing it with `b.n` (`e0 07`) always takes the inactive path, `movs r4, #1` at `0xA0855D82`. `PowerupSubsidyEvent` at `0xA0374B50` was not patched. PDS was not written.

The phone came back on USB as `22b8:6402`. `AT+CREG?` returned `+CREG: 0,1`. The subsidy prompt was gone.

| Item | Value |
| --- | --- |
| Normal / P2K / flash USB | `22b8:6402` / `22b8:6401` / `22b8:6403` |
| Sector | flash `0xA0840000`, file `0x840000`, size `0x20000` |
| Byte in the sector | `0x15D70` (file `0x855D70`) |
| Original halfword | `d0 07` |
| Patched halfword | `e0 07` |
| Original sector SHA-256 | `cbe48aae37439587731673f4d95a9d20d5b7e2e50f8b7a409ce068f2ae35e7a5` |
| Patched sector SHA-256 | `a0f028d3069d76d7d0fc89d102d7dd30e08a226e2bfc56164407ff54a84482b9` |

The public check is that code-sector hash. A full NOR image also holds PDS and user data, so its digest will not match another handset. Record your own.

The first 32-byte `BIN` erases the whole 128 KiB AMD block before programming it. A third `ERASE` selects erase-without-write. `AT+MODE=24` from `6402` enumerates mass storage `22b8:6410`, not the bootloader. Edits of SEEMs `015C`, `015D`, `01C3`, and `01C4` did not clear the lock. Three of those trials bootlooped.

The procedure is [docs/guide.md](docs/guide.md). What was tried and did not unlock the phone is [docs/what-did-not-work.md](docs/what-did-not-work.md). The dated lab journal is [research/README.md](research/README.md).

`diagnostics/` dumps, the IMEI, and the carrier letter stay on the machine that owns the phone. They are gitignored. Do not commit them.

This documents a subsidy-lock patch on a handset the author owns. The phone and the local rules are the reader's.
