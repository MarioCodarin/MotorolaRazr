# What did not unlock it

The working change is the code halfword in [guide.md](guide.md). The PDS trials below are kept so they are not repeated. The scripts that perform them exit unless `V3XX_ALLOW_PDS_WRITE=1`. `research/restore_pds_backup.py` writes the backed-up PDS block once the phone is already `22b8:6403`. It does not send `AT+MODE=24`. The dated log is [research/README.md](../research/README.md).

## PDS plaintext

The original `01C3` / `01C4` bytes 3–4 are `08 08`, and that state stayed locked. Five later edits, each written through the phone's own SEEM encrypt path and then restarted:

| Plaintext | Result |
| --- | --- |
| `01C3` / `01C4` bytes 3–4 set to `00 00` | Booted. Stayed locked. |
| `01C3` / `01C4` bytes 3–4 set to `FF FF` | Bootloop. Restored from the NOR backup after a flash-key hold. |
| `01C3` / `01C4` byte 4 only, `08 00` | Enumerated, then bootlooped. Restored the same way. |
| `015C` / `015D` set to 20 zero bytes | Booted. Stayed locked. |
| Both pairs in one shot: `01C3`/`01C4` `00 00` and `015C`/`015D` zeros | Bootloop. Restored. |

`research/restore_pds_backup.py` put the backed-up PDS block back and a live read matched it. Changing the branding string to `Brandingfree` left the subsidy records populated.

Copying the inactive all-zero subsidy records over the active copies was not run. Those zeros can fail a check the legacy 16-bit PDS checksum does not cover.

A short `BIN` still erases the rest of the 128 KiB block. The PDS headers sit on 128 KiB boundaries (`A0040000`, `A0060000`). One record is not a safe write. Do not send a third `ERASE`.

## Other public accounts

[EXL, Motofan topic 1741944](https://forum.motofan.ru/index.php?showtopic=1741944) resets protected SEEMs on older models by patching firmware, then says that procedure does not work on ordinary production Argon phones because RSA verification is not bypassed. The same note's V3xx result is an engineering i-mode prototype.

The [LPC wiki V3xx page](https://lpcwiki.miraheze.org/wiki/Motorola_RAZR_V3xx) still says retail ArgonLV RSA is not bypassed. This handset booted the one modified code sector anyway. That is an observation about this byte on this firmware, not a general write bypass.

[Jay Summet, 16 October 2007](https://www.summet.com/blog/2007/10/16/freeing-my-v3xx-phone-from-cingular/), bootloader `03.02`: a signed unbranded reflash left the subsidy prompt. The unlock in that account came from the carrier.

## Codes

Do not guess an NCK. This phone already showed the failed-attempt timeout. The owner tried `000000`, `123456`, and `654321` on the handset. All three failed. SEEM `0163` read as 14 bytes of `FF` and was not a subsidy code. SEEM `0074` in older guides is the user lock code, a different lock.
