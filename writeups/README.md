# CSCTF Writeup Index

**Division:** `[DIVISION]`  
**Team:** `[TEAM NAME]`  
**Authors:** `[TEAM MEMBERS]`

This folder contains human-readable Reverse Engineering and Pwn writeups. Each challenge folder includes an explanation of the approach, why it works, a reproducible Python solver, local validation output, and a workflow evidence capture. Literal flags are omitted in accordance with the event's submission guidance.

## Reverse Engineering

| Challenge | Main technique | Validation |
|---|---|---|
| [Dawn Control Firmware Recovery](Dawn-Firmware-Recovery/README.md) | Custom record container, CRC-32, preset-dictionary DEFLATE, CPIO, U-Boot redundant environment, repeating-key XOR | Input hash, four record CRCs, two environment CRCs, 30-byte syntax check |
| [PoshTerm Hidden Service Code](PoshTerm-Service-Code/README.md) | Embedded JavaScript analysis, hidden command discovery, MD5 guards, Julian-date key derivation, RC4 | PE hash, argument MD5, independently computed Julian date, 48-byte plaintext syntax check |
| [Carrier Shadow Stage Extraction](Carrier-Shadow-Stage-Extraction/README.md) | `.eh_frame_hdr` address-delta decoding, canonical Huffman, xorshift32, raw DEFLATE | Input hash, descriptor checksum, extracted ELF hash, authorization marker |
| [Operation Dawn — Annex Entry 06: Lockbox](Operation-Dawn-Annex-06/README.md) | ELF initialization routine, rolling XOR, rotate/add inversion | Recovered phrase accepted by the supplied executable |
| [Meridian-Class CAU Recovery](Meridian-CAU-Recovery/README.md) | Static analysis of an x86-64 ELF validator and inverse byte transformations | Local verifier analysis and reproducible solver |

## Pwn

| Challenge | Main technique | Local validation |
|---|---|---|
| [Forge — House of Force](Forge-House-of-Force/README.md) | `temper()` heap overflow, tcache/unsorted-bin leaks, House of Force, `__malloc_hook` overwrite | Shell marker and `id` output using the bundled glibc 2.27 |
| [Relic — ret2csu](Relic-Return-to-CSU/README.md) | Stack overflow, three-stage ret2csu, `.bss` pivots, GOT leak, libc `system()` | Shell marker and `id` output using the bundled glibc 2.31 |
| [Stepper — Staged Shellcode](Stepper-Staged-Shellcode/README.md) | Six-byte instruction filter, persistent guest registers, runtime `read@plt` derivation, RWX second stage | All setup steps accepted; staged shell marker and `id` output |

**Remote verification note:** the three Pwn chains were validated against their supplied local challenge builds. Remote DNS resolution was unavailable during this run, so no remote flag is claimed or included. Re-run the supplied solvers against the authorized event instances to complete remote validation.

## Submission note

Fill in the division, team name, and author fields before sending the Markdown files to the organizers. Review the event template before submission. Unverified remote results are explicitly labeled rather than presented as completed flag retrieval.
