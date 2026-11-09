# CSCTF Reverse Engineering — Dawn Control Firmware Recovery

**Division:** `[DIVISION]`  
**Team:** `[TEAM NAME]`  
**Authors:** `[TEAM MEMBERS]`  
**Category:** Reverse Engineering  
**Artifact:** `firmware.bin` (1,048,576 bytes)  
**SHA-256:** `ae253e80cfca3035fe1e882c3c26a75b1d701f1b1bb343ba290d590573bc4313`

## 1. Objective

The supplied 1 MiB file is a compact recovery bundle for a DAWN-Control field radio. The useful data is stored in four CRC-protected records rather than in a conventional full-flash layout. The recovery token is stored in the root filesystem in an obfuscated form, and the init script explains how the device reconstructs it at boot.

The binary was treated as untrusted data. No firmware or extracted shell script was executed.

## 2. Identify the container

The first eight bytes are:

```text
44 57 46 57 01 00 04 00
```

This is the `DWFW` magic, version 1, followed by a record count of four. Each record-table entry is 20 bytes:

- 8-byte ASCII record name
- 32-bit little-endian file offset
- 32-bit little-endian byte length
- 32-bit little-endian CRC-32

The four records are:

| Record | Offset | Length | CRC-32 |
|---|---:|---:|---:|
| `loader` | `0x0200` | 111 | `e08559b1` |
| `ubootenv` | `0x0270` | 16,384 | `0e0748da` |
| `msgcat` | `0x4270` | 258 | `5a21c5b2` |
| `rootfs` | `0x4380` | 633 | `65047329` |

The solver checks the SHA-256 of the complete input, bounds-checks every record, and verifies all four CRC values before parsing any payload. This separates genuine container data from unused padding and catches incorrect offsets immediately.

## 3. Recover the root filesystem

The `rootfs` record begins with a zlib stream that requires a preset dictionary. The `msgcat` record is that dictionary: passing it to Python's `zlib.decompressobj(zdict=...)` successfully inflates the record into a 2,560-byte `newc` CPIO archive.

The archive contains ten entries, including:

- `etc/config/radio`
- `etc/init.d/S40admin`
- the normal init scripts and system banner

`etc/config/radio` stores `admin_token` as hexadecimal bytes. The important point is that the token is not meant to be used directly; the boot script describes the transformation that produces the runtime key.

## 4. Reconstruct the runtime key

The relevant part of `etc/init.d/S40admin` performs these operations:

1. Read `ethaddr` from the U-Boot environment and remove the colon separators.
2. Read `admin_token` from `etc/config/radio`.
3. Convert the token from hexadecimal into bytes, two hex characters at a time.
4. XOR each token byte with the corresponding byte of the MAC address, repeating the six-byte MAC as necessary.
5. Write the result to `/var/run/admin.key`.

This is a repeating-key XOR, not a cryptographic key derivation function. The script itself is the evidence for the operation and key source.

## 5. Select the correct U-Boot environment

The `ubootenv` record contains two 8 KiB redundant environment copies. Each copy has a little-endian CRC-32, a one-byte redundancy flag, and NUL-separated `key=value` entries.

Both copies pass their CRC checks, so selecting the first copy merely because it is valid would be insufficient. Their contents distinguish the stale and active states:

- Copy 0: flag `6`, `recovery=legacy`
- Copy 1: flag `7`, `recovery=ready`

The second copy is the recovery-ready environment. Its `ethaddr` is the value used by the init script, so the solver selects it rather than the legacy copy.

## 6. Reproducible recovery

Run the static solver with Python 3:

```bash
python3 solve.py firmware.bin
```

The script validates the outer SHA-256, all record CRCs, the dictionary-based decompression, the CPIO structure, both environment CRCs, and the active environment marker. It then applies the exact repeating-MAC XOR described by `S40admin`.

To print the recovered plaintext locally, use:

```bash
python3 solve.py firmware.bin --show
```

The default mode intentionally does not echo the recovered token into logs or screenshots.

## 7. Validation

The recovery is supported by independent checks at each layer:

- The input SHA-256 matches the challenge artifact.
- All four container records pass CRC-32.
- The preset-dictionary DEFLATE stream expands to exactly 2,560 bytes.
- The CPIO parser reaches `TRAILER!!!` and extracts the expected configuration and init script.
- Both U-Boot environment copies pass CRC-32, but only one has `recovery=ready`.
- The XOR result is 30 bytes and matches the required `CSCTF{...}` syntax.

No device boot, network interaction, or execution of firmware code was needed.

## 8. AI methodology

- **Tool/model:** ChatGPT GPT-6 was used as an analysis assistant to organize the static findings and help draft a reproducible parser. The binary transformations and final checks were independently implemented in Python.
- **Meaningful automation:** Python's standard library (`hashlib`, `struct`, `zlib`, `re`) validates the container, inflates the dictionary-compressed root filesystem, parses `newc` CPIO and U-Boot environment records, and reproduces the shell script's XOR operation.
- **Human checks:** The input hash and each CRC were compared against the artifact; the decompressed size and CPIO trailer were checked; both environment copies were independently CRC-checked; the active `recovery=ready` marker was confirmed before using its MAC.
- **Safety:** The firmware and extracted shell script were inspected as data. Neither was executed.

### Workflow evidence

The genuine terminal workflow screenshots are collected in the [consolidated team writeup](../CSCTF-Participant-Writeup.md#workflow-screenshots).
