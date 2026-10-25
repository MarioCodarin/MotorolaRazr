# Motorola RAZR V3xx USB investigation — 24 September 2026

The procedure is [docs/guide.md](../docs/guide.md). Dump files stay in this directory and are not committed. The September notes below are the earlier log. The 25 October result supersedes the paragraphs that still say the write path is unsolved. Another phone's full NOR SHA-256 will not match the fingerprint in the table. The public check is the code-sector hash in the guide.

## Result

The Mac can communicate with this phone through both its USB modem and P2K05 interface. The PDS ident in the NOR backup names the original flex `USIZRGBLH3GITR26111058` (H3G Italy); the active branding string was later changed to `Brandingfree`. On 25 October 2026 the subsidy check was forced inactive by one Thumb halfword in the code sector at `0xA0840000`. The owner confirmed the prompt was gone, the phone came back as `22b8:6402`, and `AT+CREG?` returned `+CREG: 0,1`. The procedure, the hashes, and the restore command are in [the research notes](../research/README.md). `nor_a000.bin` itself still holds the original halfword `d0 07` at file offset `0x855D70`.

## Device observations

- Mac: Apple silicon, macOS 27.0.
- USB normal mode: Motorola `22b8:6402`; P2K05 mode: `22b8:6401`; flash mode: `22b8:6403`.
- Modem identifies `MODEL=RAZRV3xx` and firmware `R26111LD_U_96.A0.0ER`.
- Flash interface reports `R26111LD_U_96.A0.0ER:Brandingfree`; this does not establish that the carrier lock is removed.
- With the SIM present, `AT+CPIN?` returned `READY`, `AT+CREG?` returned `0,0` (not registered), and `AT+CSQ` returned `27,99` (radio signal reported).
- After the retry lockout cleared, the screen changed from `contatta l'operatore` to `inserisci password blocco sim`. A fresh `AT+CPIN?` still returned `READY`, so this prompt is not for the CoopVoce SIM's PIN; in context it is the phone's carrier-lock password prompt.
- The flash `RQHW` response ended in `0302`, consistent with boot revision 03.02, but this was not independently checked on the phone's screen.
- SEEM `0163_0001` read as 14 bytes of `FF`, so it did not yield a subsidy code. SEEM `0074` cited in old guides is the phone's user lock code, a different lock.

## Backups

The two NOR regions described for V3xx in FlashTerminal were read using its K3 RAM loader. This loader ran in RAM; flash memory was not changed. Every read response was checked for expected size and framing, and twelve random blocks per region were compared against fresh phone reads.

| File | Region | Size | SHA-256 |
| --- | --- | ---: | --- |
| `nor_a000.bin` | `A0000000–A1FFFFFF` | 33,554,432 bytes | `07c14350f7216f011d9a2e3a40297160c45de7d001f2fd4b64d1252f6f2226ae` |
| `nor_b400.bin` | `B4000000–B5FFFFFF` | 33,554,432 bytes | `5f8a8d027da6887ad4ca6810c9285df0b5ca5a2572155285ada526202b5d0a4e` |

Small read-only SEEM copies are also in this directory. The dump files may contain personal data and device identifiers; keep them private and do not upload them to a public service. The directory is accessible only to the local user, and both NOR files have mode `600`.

`IMEI.txt` contains the 15-digit IMEI read from the phone's modem for a direct carrier-identification request to Motorola. It has mode `600`; do not post it publicly.

## Software checked

- [P2KC](https://github.com/pulkomandy/p2kc): successfully connected to this V3xx in P2K05 mode and read SEEMs. Its source has no verified carrier-unlock operation. The local source copy has minimal compatibility edits to compile on this Mac.
- [FlashTerminal](https://github.com/EXL/FlashTerminal): documents V3xx flash dumping with `K3_RAMDLD_0320.ldr`; the dump worked. It is not a subsidy-unlock tool.
- Historical V3xx unlock procedures found in [GSM-Forum](https://forum.gsmhosting.com/vbb/f166/help-how-unlock-v3xx-463849/) and [Elektroda](https://www.elektroda.pl/rtvforum/topic850860.html) generally require Smart-Clip or a hardware test point. The claimed P2K Commander SEEM toggle only changes SIM-screen access and is not evidence of a network unlock.
- [Motorola support](https://en-gb.support.motorola.com/app/answers/detail/a_id/175421/~/unlock-my-phone-from-a-specific-carrier) identifies a subsidy-code prompt as a carrier lock. [CoopVoce's FAQ](https://www.coopvoce.it/portale/assistenza/tutte-le-faq.html) identifies Vodafone as its current host network.

## 24 September follow-up: software unlock research

EXL's [P2K software-unlock research](https://forum.motofan.ru/index.php?showtopic=1741944) identifies four subsidy-related SEEMs: `015C`, `015D`, `01C3`, and `01C4`. Its demonstrated procedure on older models patches firmware to permit writes to protected SEEMs, then replaces those records. EXL reports a V3xx i-mode *engineering prototype* unlock, and explicitly says this firmware-patch procedure does not work on ordinary production Argon phones because their RSA verification has not been bypassed. That prototype is not evidence that the procedure works on this apparently retail V3xx with bootloader 03.02 and `R26111LD_U_96.A0.0ER`.

Read-only P2K requests on this phone returned 0-byte files for `015C_0001` and `015D_0001`, and 32-byte files for `01C3_0001` and `01C4_0001`. The latter both begin `00 00 00 08`; this is an observation, not a decoded lock status. The NOR dump contains two regions beginning `PDS_3022` at `A0040000` and `A0060000`. Their contents are not yet parsed into validated SEEM records. These observations narrow the storage and protection mechanisms, but do not identify a safe byte edit or provide a tested restoration path. **No SEEM upload, flash erase/write, or code entry was performed.**

A software-only method would require, in order: (1) identify and validate the phone's production/engineering security state; (2) obtain a working, device-specific way to write those protected records without violating the production signature check; (3) decode the PDS record format and integrity fields; (4) demonstrate backup restoration and test the candidate change on matching spare hardware. Steps 2–4 remain unsolved for this handset. A normal firmware reflash is not an unlock method and risks overwriting device-specific PDS data.

Further offline adaptation found the exact firmware protection table and built an experimental ArgonLV RAM loader from Hitagi. See [the research notes](../research/README.md) and the read-only `research/firmware_table.py` analyzer. The phone had disconnected from USB before a loader test could begin on 24 September. No unlock write was made.

On 28 September the phone reconnected. The known K3 loader reported a 64 MiB AMD/Spansion family NOR ID. Hitagi's ArgonLV AMD build then ran from a fresh bootloader session, and four checksum-verified reads matched the backups, including both PDS headers. The phone returned to normal mode with the SIM ready. This establishes a read-only path with open-source code; the `PDS_3022` format, direct-write behavior, and restore path remain unverified. No NOR erase/write or SEEM upload was made. The detailed log is in [the research notes](../research/README.md).

## 25 October 2026

The code-sector write is recorded in the research notes. PDS was left equal to this NOR backup. Five earlier edits of SEEMs `015C`, `015D`, `01C3`, and `01C4` did not clear the lock; three bootlooped and were restored from `nor_a000.bin` after a manual flash-key hold. `AT+MODE=24` from `22b8:6402` enumerates mass storage `22b8:6410`, not the bootloader. Flash mode on this phone is the handset flash-key hold, product `22b8:6403`.

To put the original halfword back, enter that flash mode and run `python3 research/patch_subsidy_sector.py --restore`.
