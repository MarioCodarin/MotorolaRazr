# V3xx unlock adaptation (updated 25 October 2026)

The procedure is [docs/guide.md](../docs/guide.md). The September and 2 October sections below are the earlier log. The 25 October result supersedes them.

## Result on 25 October 2026

This handset (`R26111LD_U_96.A0.0ER`, boot `03.02`) boots with the subsidy check forced inactive. The owner confirmed the SIM prompt was gone. The phone enumerated as USB `22b8:6402`, and `AT+CREG?` returned `+CREG: 0,1` (registered, home network). `diagnostics/nor_a000.bin` was not modified. PDS was not written in this pass.

The change is one Thumb halfword inside signed code, not a PDS edit. The five earlier plaintext trials of SEEMs `015C` / `015D` / `01C3` / `01C4` stayed locked or bootlooped. Those records were restored from the NOR backup before this patch. A same-day live read of both 128 KiB PDS copies matched that backup byte for byte, and the subsidy elements were not in either copy.

### The instruction

`SubsidyLockDispatch` at `0xA0855D58` loads element `0x9BD` and treats the byte values `0x00`, `0x11`, and `0xFF` as inactive. The inactive path is `movs r4, #1` at `0xA0855D82`. The first of those three compares is Thumb `beq.n` at `0xA0855D70` (`d0 07`). Replacing it with `b.n` (`e0 07`) always takes that path. File offset `0x855D70`. The following byte stays `07`.

`PowerupSubsidyEvent` at `0xA0374B50` (`42 9a d0 09`, `cmp` / `beq`) is a different check and was not patched. Element `0x9BD` is read through RAM object `0x821678A8`. It is above the SEEM stride limit `0x420`, and the only value record in the image (file `0xCD6B8`) is already six zero bytes. Halfwords `09 BD`, `06 E5`, and `06 C7` are absent from both live PDS copies.

### The write

AMD main blocks are 128 KiB (`tools/Hitagi/flash_amd16.c`). `ERASE` only increments the loader mode. Two `ERASE` commands select buffer programming. A third selects erase-without-write. The first `BIN` whose address is 128 KiB-aligned erases that whole sector, then programs 32 bytes. The loader acks the `BIN` before the erase finishes.

| Item | Value |
| --- | --- |
| Sector | `0xA0840000`, file `0x840000`, size `0x20000` |
| Byte inside the sector | `0x15D70` |
| Original halfword | `d0 07` |
| Patched halfword | `e0 07` |
| Original sector SHA-256 | `cbe48aae37439587731673f4d95a9d20d5b7e2e50f8b7a409ce068f2ae35e7a5` |
| Patched sector SHA-256 | `a0f028d3069d76d7d0fc89d102d7dd30e08a226e2bfc56164407ff54a84482b9` |
| Full NOR SHA-256, unchanged | `07c14350f7216f011d9a2e3a40297160c45de7d001f2fd4b64d1252f6f2226ae` |

`research/patch_subsidy_sector.py` is that procedure. With no flag it only checks the backup. The check requires the firmware ident, halfword `d0 07`, and the original code-sector SHA-256. It prints the full-image digest and does not require it to match this handset. `--write` programs the patched sector. `--restore` programs the original slice from `diagnostics/nor_a000.bin`. Both refuse to run unless the phone is already `22b8:6403`. Neither sends `AT+MODE=24` (from `6402` that enumerates mass storage `22b8:6410`) and neither calls `write_pds_block` (that writer is hardcoded to `0xA0040000` and requires a `PDS_` header).

On the handset, before any `ERASE`: product id `0x6403`, Hitagi `RQSW` `Hitagi SW v1.0:Hitagi FLEX v1.0`, `RQFI` `007E3000`. The live sector matched the backup. After `ERASE`, `ERASE`, `ADDR 0xA0840000`, and 32-byte `BIN`s, the readback matched the patched image, including `e0 07`. `RESTART` then dropped the phone off the bus. It later came back as `22b8:6402`.

Public notes still say retail ArgonLV RSA is not bypassed ([LPC wiki, Motorola RAZR V3xx](https://lpcwiki.miraheze.org/wiki/Motorola_RAZR_V3xx); [EXL](https://forum.motofan.ru/index.php?showtopic=1741944)). This unit booted the modified sector anyway. That is an observation about this handset and this byte, not a general write-bypass.

### Restore

Hold the phone's flash key until USB shows `22b8:6403`, then:

```sh
python3 research/patch_subsidy_sector.py --restore
```

The on-disk NOR file still contains `d0 07` at `0x855D70`, so it is the restore source. Do not send a third `ERASE`.

The RAM loader used for the read and the sector write was `tools/Hitagi/hitagi.bin`. That file contains the `SCCRUN` command from the local Argon patch. `SCCRUN` was not sent during the sector write. Upstream is [MotoFanRu/Hitagi](https://github.com/MotoFanRu/Hitagi) branch `argon` at `d6ebbec`; the local delta is `research/patches/hitagi-scc.patch` and was not pushed there. [EXL/FlashTerminal](https://github.com/EXL/FlashTerminal) `master` at `8ae1de7` supplied the USB framing and was not modified. [pulkomandy/p2kc](https://github.com/pulkomandy/p2kc) `master` at `3aa4747` has a local macOS fix for `usb_dev_handle*` comparisons (`research/patches/p2kc-macos-usb-handle.patch`), also not pushed upstream.

## Verified on this phone's backup

- Firmware `R26111LD_U_96.A0.0ER`, boot revision reported as `03.02`.
- `diagnostics/nor_a000.bin` has SHA-256 `07c14350f7216f011d9a2e3a40297160c45de7d001f2fd4b64d1252f6f2226ae`.
- Its 15-entry P2K protected-SEEM dispatch table starts at `A07DB220`. The handler used by the four subsidy-related entries is Thumb address `A07D53FD`. The record addresses are `015D=A07DB250`, `015C=A07DB260`, `01C3=A07DB290`, `01C4=A07DB2A0`. `firmware_table.py` checks the entire table structure and prints these offsets without modifying anything.
- The firmware routine at `A07ADF00` searches that table in 16-byte records and calls the selected handler. This was checked by ARM big-endian Thumb disassembly with `arm-none-eabi-objdump`.
- USB P2K reads returned 0 bytes for `015C` and `015D`, and 32 bytes for `01C3` and `01C4`.
- Two NOR regions start with `PDS_3022` at `A0040000` and `A0060000`. A read-only parser now walks the records in both. The first region is active (`FFF9`), with 82 records and a valid 16-bit checksum stored in SEEM `02C9`; the second is inactive (`FFF0`), with 64 older records. The active copy contains `015C` and `015D` as 32-byte records, and `01C3` and `01C4` as 40-byte records. Their data is not printed by the analyzer.
- SEEM `02CA`/`02CB` are plaintext `@(#)` ident records, 40 bytes with NUL padding. The same 40-byte size is therefore used for ordinary ident data, so the extra 8 bytes on `01C3`/`01C4` are not by themselves a MAC trailer. Active idents: firmware `R26111LD_U_96.A0.0ER`, branding `Brandingfree`. Inactive/superseded ident: flex `USIZRGBLH3GITR26111058` (H3G Italy). The subsidy records stayed populated after the branding string was changed.
- The inactive PDS stores zeros in `015C`/`015D`/`01C3`/`01C4`; the active copies of those records are high-entropy and unique in both NOR dumps. P2K `01C3`/`01C4` (32 bytes, both beginning `00 00 00 08`) do not occur in `nor_a000.bin` or `nor_b400.bin`. P2K `015C`/`015D` are empty. This is a runtime transform, not a wrapper around the stored bytes.
- The shared Thumb handler at `A07D53FD` is an access-control gate: it range-checks the SEEM id and writes status `7` or `8` into the caller buffer. It is not the encrypt/decrypt routine. AES S-boxes are absent from this firmware image; the `3DES` strings in the dump are TLS cipher-suite names.
- Live P2K05 on 28 September 2026 (phone in `22b8:6401`): `015C`/`015D` return a 13-byte error frame ending `08`, matching that handler. `01C3`/`01C4` still return the same 32-byte runtime view as the earlier files (`00 00 00 08 08 00 00 00 … FF`). MEMACS command `0x16` returns error `03` at `80000000`, `A0040000`, and `00000000` — memory access is disabled on this production build.
- Firmware contains a complete Blowfish implementation (P-array at `A082993C`, S-box 0 at `A0829984`, Schneier test vector `"7654321 Now is the time for"`). Key setup `A081B552` accepts 4–56 byte keys. Production wrappers: decrypt `A081B83A` / encrypt `A081B84C`. Strings `seem_fdi_outside_seem_access.c` and `seem_element_data.c` check a decrypted SEEM/record id after this layer.
- Offline Blowfish-ECB/CBC with IMEI, flex ident, branding, and several PDS records as keys does not produce the P2K `01C3` view or a leading `01C3`/`015C` id. The session key is loaded into a runtime crypto object (`A0811852` / `A081E0A0`); it is not a trivial function of the IMEI. Flash-mode SRAM would not hold that OS key.

Run the read-only analyzer:

```sh
python3 research/firmware_table.py diagnostics/nor_a000.bin
python3 research/pds.py diagnostics/nor_a000.bin --seems diagnostics
python3 -m unittest discover -s research -p 'test_*.py'
# live P2K (AT+MODE=8, read-only): python3 research/p2k_probe.py
```

## Candidate path and current stop points

[EXL's P2K software unlock work](https://forum.motofan.ru/index.php?showtopic=1741944) resets these protected SEEMs on older models using patched firmware. The same researcher unlocked an *engineering* V3xx i-mode prototype and says the method does not work on ordinary production Argon phones because signed firmware verification is not bypassed. Applying its patched firmware directly to this handset is unsupported.

[Hitagi's experimental ArgonLV branch](https://github.com/MotoFanRu/Hitagi/tree/argon) documents RAM downloaders that can access NOR without replacing the signed boot firmware. The initial Intel driver build was for the wrong flash family. The known K3 loader returned `RSFI: 30017E30,04000000,0000020C`, consistent with a 64 MiB AMD/Spansion type NOR; a [V3xx teardown](https://electronics360.globalspec.com/article/3633/motorola-v3xx-razr-mobile-phone-teardown) identifies a Spansion 512 Mb NOR package. The ArgonLV `FLASH_TYPE=amd16` build was successfully uploaded from a fresh bootloader session. It responded to `RQHW`, `RQFI`, and `READ`. Four 16-byte reads at `A0040000`, `A0060000`, `A07DB220`, and `B4020000` had valid response checksums and matched the backup byte for byte. The phone then restarted into normal mode and answered AT commands with `+CPIN: READY`.

The first upload attempt had timed out because it was made while the K3 loader was already running at the same `80000038` RAM address. The phone restarted normally. This showed why the custom loader must be uploaded only from a fresh bootloader session. The working test issued no `ERASE`, no `BIN` to a NOR address, and no persistent write.

Hitagi's AMD sector write was verified on 25 October, for the one code sector named above. The PDS record layout and the active copy's legacy checksum are verified, using the [period PDS format description](https://www.howardforums.com/threads/pds-creator-for-free.728634/page-3). The description was written for older models, so it does not establish how this V3xx validates protected record contents. A direct PDS edit still needs the encoding/authentication scheme and a safe way to restore both PDS copies. Copying the inactive all-zero subsidy records into the active area is not a tested unlock: those zeros may fail a runtime authenticator the legacy 16-bit checksum does not cover. The 25 October patch above is the one later exception: a full 128 KiB sector, read back before reboot. A short `BIN` still blanks the rest of the erased block. Do not send a third `ERASE`.

In the current Hitagi code, `ERASE` changes the loader's write mode; a later `BIN` aimed at NOR calls `flash_unlock` and may erase a complete flash block before programming. The `PDS_3022` headers are at 128 KiB spaced addresses (`A0040000`, `A0060000`). A short write to one record is therefore not a safe experiment: it may erase more PDS data than the supplied packet restores. The loader also uses Intel-style NOR commands, so chip identification is essential.

The phone was absent from USB on 24 September, then reconnected for the read-only loader checks on 28 September.

## Next checks, in order

1. The Blowfish session key is derived at `A08130AC` / `A0856C40` from the SoC unique-id ASCII hex (36-byte buffer, 3-round scramble), then `BF_set_key` at `A0811852`. On this handset the scrambled unique id, used as a Blowfish-ECB key, does not decrypt PDS `015C`/`01C3` to a structured plaintext or to the P2K `01C3` view. The IIM window read as mostly zeros in the bootloader, a second IIM window timed out, and flash `READ_OTP` was blank. The remaining secret is not in the NOR dump. The unique id itself is not in this tree.
2. Do not construct or flash unlocked PDS records until a key is recovered that round-trips the stored blobs.
3. Validate AMD/Spansion write geometry before any NOR `ERASE`/`BIN`. MEMACS stays error `03`.

Public notes on this platform: [LPC wiki, Motorola RAZR V3xx](https://lpcwiki.miraheze.org/wiki/Motorola_RAZR_V3xx) states that retail ArgonLV RSA is not bypassed, and that international subsidy bypass needs a box.

The paragraphs above record the state on 28 September. The 25 October section is the result: one code halfword, not a PDS guess. Do not enter guessed subsidy codes; the phone has already shown the failed-attempt timeout.

## Update, 2 October 2026

Picked up where the above left off. The crypto oracle described above (encrypt arbitrary plaintext into valid `01C3`/`01C4` ciphertext via OS SEEM `03FF`, `research/os_oracle.py`/`os_oracle_01c3.py`) works reliably and was re-verified live. It is not the blocker; the blocker is not knowing which plaintext actually disables the lock.

Four live plaintext trials for the `01C3`/`01C4` lock bytes (offsets 3–4 of the 32-byte record, originally `08 08`), each via write→verify→restart, round-tripped through `research/unlock_01c3_ff.py` / `unlock_01c3_byte4.py`:

- `08 08` (original): locked, as expected.
- `00 00` (both bytes, `os_oracle.py`/`unlock_01c3_tail.py` style): boots fine, phone stays locked.
- `FF FF` (both bytes): hangs/bootloops. Required a manual rescue into `22b8:6403` (hold phone's own flash-mode entry) to restore.
- `08 00` (byte 4 only, byte 3 left at `0x08`): appeared to boot (`6403→6402` observed), then bootlooped moments later anyway. Required a second manual rescue.

Both bootloops were recovered cleanly via `research/restore_pds_backup.py` (full verified restore of the backed-up PDS block from `diagnostics/nor_a000.bin`), confirmed byte-identical afterward via live P2K read. The phone is currently in its original, fully intact, locked state.

Same exercise for `015C`/`015D` (the ACL-protected 20-byte record, decrypted via the `015F`-aliasing oracle in `decrypt_015c_via_015f.py`): setting it to all-zero (`os_oracle.py`'s original `UNLOCK_20`) also boots fine but stays locked.

**Conclusion: this is very likely not a "haven't found the right byte" problem.** External research corroborates:

- [EXL's P2K software unlock writeup](https://forum.motofan.ru/index.php?showtopic=1741944) (already cited above) states this class of technique does not work on retail ArgonLV firmware because signature verification isn't bypassed — only worked on an engineering/unlocked unit.
- The original (non-xx) V3's subsidy-lock removal tools (P2K Easy Tool, "Motorola Unlocker 2005") rely on a bootloader downgrade (`scotty2_8.26_downgrader`, "bl_826-828_to_07d0") that specifically strips RSA signature checking introduced in V3 bootloader 8.26+. No ArgonLV-equivalent downgrader is documented anywhere found; the Hitagi/FlashTerminal loader table (`tools/Hitagi/ReadMe.md`) only has *read*-bypass ("Hacked RSA_Read") loaders for ArgonLV phones, never write/flash bypasses — telling, since this is the same community that would have published one if it existed.
- A first-hand account of debranding a V3xx with a full firmware reflash ([summet.com blog](https://www.summet.com/blog/2007/10/16/freeing-my-v3xx-phone-from-cingular/), same bootloader `03.02` as this phone) explicitly states that flashing generic/unbranded firmware *without* the carrier-granted unlock still leaves the "Subsidy Lock code" warning — i.e. even a full code+PDS reflash via official signed firmware doesn't clear the lock on its own; the actual unlock in that case came from the carrier.

Our PDS-only writes don't need to pass RSA (they're plain NVM data, not signed code), and they do flash/verify successfully — but the lock decision evidently depends on something else in the signed firmware/boot chain that a pure-data edit can't satisfy, and invalid/inconsistent values in that data trigger a hang rather than a graceful fallback.

Remaining paths, none pursued further this session: (1) the carrier's actual NCK code (out of scope — the point was to avoid needing this); (2) a full "factory erase" SBF reflash sourced from an already-unlocked donor phone of matching hardware/band — researched, but every concrete source found is either a dead 2008–2010-era link or gated behind a paid professional unlock-tool subscription (Smart-Clip/SCout), and flashing an unverified decade-old firmware binary is a materially higher, much-less-recoverable risk than the PDS-only experiments above; (3) genuine JTAG/boundary-scan hardware access to the SoC — different equipment and risk category entirely, not attempted.

### Further static RE and a fifth live trial

Pushed static analysis further with Ghidra (`brew`-installed, headless, `ARM:BE:32:v5t`). Full-binary auto-analysis OOMs repeatedly (even at 6G heap) in `ArmAnalyzer.flowConstants`, almost certainly due to large embedded image/asset blobs being mis-walked as code. Targeted disassembly (no full auto-analysis) confirmed:

- The 15-entry protected-SEEM table's shared handler (`A07D53FC`) and the table-scan dispatcher (`A07ADF00`) are reached only through an indirect function-pointer dispatch table (found by searching for the handler's address as *data*: one hit, at `A0787640`, inside a much larger **103-entry generic ID→handler+permission-flags dispatch table** spanning `A0787558`–`A0787A2C`). The function that walks this table (`~A076D900`) is itself parameterized (table base passed in a register), so it's shared/generic infrastructure, not proof either way of USB-only vs. internally-reachable.
- The SEEM crypto wrappers (`A081B83A`/`A081B84C`, matching `seem_crypt.py`'s docstring) have exactly 4 external callers total, all of which are themselves further generic buffer-crypto wrappers (shared with e.g. the TLS path) — no subsidy-specific business logic found by walking this chain either.
- Exhaustive string search (plain + UTF-16LE/BE, both NOR dumps) for the phone's actual lock-screen text ("contatta l'operatore" / "operatore" / "contact...provider") found **no matches at all** — the displayed message isn't stored verbatim in either firmware dump, so it's either composed from indexed/ID-based trace strings (consistent with the `"22DL_SUBSIDY_LOCK_GSM_SP"`-style length-prefixed symbol table found earlier) or lives somewhere not captured by these two dumps.
- `nor_b400.bin` was checked as a candidate separate baseband/modem firmware (which often independently owns SIM-lock enforcement on these platforms) — it isn't one. It contains user-data/filesystem content, including a personal name in the user-data region, and likely a secondary AP code bank, same firmware-version family as `nor_a000.bin`, no "subsidy" string anywhere in it.

Confirmed via the phone's own screen that there **is** an interactive numeric code-entry UI (not just a static message) — standard Motorola subsidy-password entry. Public info on attempt limits is inconsistent across sources (one claims 255 attempts with a 60-minute delay, another claims some models permanently lock after as few as 10) and this project's own earlier session already triggered at least one failed-attempt timeout — so guessing codes carries real, unquantified risk. The three generic publicly-documented default codes (`000000`, `123456`, `654321` — not a paid/IMEI-derived lookup) were tried by the phone's owner directly: all failed, as expected for a genuinely carrier-locked retail unit.

Fifth live PDS trial, `unlock_combined.py`: wrote **both** record pairs in one shot — `01C3`/`01C4` bytes[3:5] `08,08→00,00` (individually known to boot fine) **and** `015C`/`015D→`20 zero bytes (also individually known to boot fine) — testing whether the two records are cross-validated against each other. Result: bootlooped (recovered via the same verified-backup restore as before, 7s to `6402`). This is at best inconclusive for the cross-validation theory, since it appended roughly double the PDS log records of any single-record attempt — plausibly a capacity/indexing side-effect unrelated to the lock logic rather than a security response. Either way it doesn't open a clear next guess.

At this point five live write attempts (four single-record variants, one combined) have been made, three of which bootlooped and required manually forcing the phone into flash mode (`22b8:6403`) to recover, each time cleanly. No further live PDS-write attempts are planned without a qualitatively new piece of evidence (not just another byte-value guess) — the repeated bootloop/manual-rescue cycle is a real, recurring cost to the phone's owner, not just a risk absorbed by this process.

### Ghidra, properly this time, and where the crypto call chain actually bottoms out

Root cause of the earlier Ghidra OOM found: full auto-analysis on the whole 32MB image blows the heap in `ArmAnalyzer.flowConstants`, reproducibly, even at 6G — almost certainly from large embedded image/asset blobs elsewhere in the file being mis-walked as code. Isolating a 2 MiB slice (`A0700000`–`A0900000`, covering every address of interest: the ACL table/gate, both dispatchers, and the whole crypto chain) and running full auto-analysis on *that* completes in ~17s with no errors, confirming the OOM is a whole-file-size artifact, not a sign the binary is unanalyzable. (Decompilation itself isn't available — this Ghidra release ships prebuilt `decompile` natives only for `win_x86_64`/`linux_x86_64`, not `mac_arm_64`; building it from source would need the full Ghidra dev/gradle environment, judged not worth the detour versus reading disassembly directly.)

With working cross-reference resolution, traced the crypto chain (`seem_crypt.py`'s `A081B83A`/`A081B84C` wrappers → `A0811902`/`A0811952` → the session-key/decrypt-or-encrypt dispatcher at `A081E41C`, which branches on an opcode byte to `A081E12C` (decrypt) or `A081E2E8` (encrypt)) up through its callers, each step confirmed to have only 1–2 direct callers (real signal, not dispatch-table noise). It terminates at a pair of functions (`A0811F54` write / `A08120AE` read) that are themselves generic buffered block I/O with a type-dispatch byte read from a tiny fixed low-memory offset (`0x58`) — i.e. a VFS-style file-descriptor abstraction, not anything subsidy-specific. This is the file-I/O chokepoint the whole OS's storage goes through (matches the `seem_fdi_outside_seem_access.c` / `seem_element_data.c` module names seen in strings — FDI = File Descriptor Interface). Finding "where subsidy lock gets checked" from here would require enumerating every file-open call site in the firmware that passes a SEEM-id as a path/handle, which is a different and much larger search than following this crypto chain — not tractable by hand without the symbol table this firmware doesn't ship.

That closed the Blowfish/FDI chain. It did not find the subsidy decision. The 25 October disassembly did: `SubsidyLockDispatch` at `0xA0855D58`, patched at `0xA0855D70`. The protected-SEEM ACL and the FDI bottoms were not on that path.
