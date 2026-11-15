# CSCTF Writeup Index

**Division:** `[DIVISION]`  
**Team:** `[TEAM NAME]`  
**Authors:** `[TEAM MEMBERS]`

This index covers the Reverse Engineering and PWN challenges for which the analysis and local validation are complete. Each listed challenge folder includes a human-readable explanation and a reproducible solver. Three genuine terminal workflow screenshots are collected in the team-level submission report. Literal flags, recovered keys, session nonces, session keys and live instance details are intentionally omitted.

**Single-file submission draft:** [CSCTF-Participant-Writeup.md](CSCTF-Participant-Writeup.md)

## Reverse Engineering

| Challenge | Approach | Validation |
|---|---|---|
| [Dawn Control Firmware Recovery](Dawn-Firmware-Recovery/README.md) | Custom record container, CRC-32, preset-dictionary DEFLATE, CPIO, redundant U-Boot environment, repeating-key XOR | Input hash, four record CRCs, both environment CRCs, recovered-length and syntax checks |
| [PoshTerm Hidden Service Code](PoshTerm-Service-Code/README.md) | PE/embedded JavaScript analysis, hidden command, MD5 guards, Julian-date derivation, RC4 | PE hash, argument MD5, independently derived Julian date, decrypted-length and syntax checks |
| [Carrier Shadow Stage Extraction](Carrier-Shadow-Stage-Extraction/README.md) | `.eh_frame_hdr` address-delta stream, canonical Huffman, xorshift32, raw DEFLATE | Input hash, descriptor checksum, extracted ELF hash, static marker inspection |
| [Operation Dawn — Annex Entry 06: Lockbox](Operation-Dawn-Annex-06/README.md) | ELF initialization routine, rolling XOR, rotate/add inversion | 44-byte inverse and forward-transform equality; original ELF not executed |
| [Meridian-Class CAU Recovery](Meridian-CAU-Recovery/README.md) | Static x86-64 analysis, inverse XOR-shift and modular multiplication | Three 64-bit block hashes reproduced; 24-byte ASCII length verified |
| [Split Horizon — Vireo Parser Differential](Split-Horizon/README.md) | .NET IL, PE static data, HMAC-derived frame key, TCP/PCAP reassembly, JSON parser differential | Eight commands decrypted; executed/logged waypoints distinguished; audit chain and Ed25519 signature verified |


## PWN

| Challenge | Approach | Validation |
|---|---|---|
| [Forge — House of Force](Forge-House-of-Force/README.md) | Tcache heap-pointer leak, unsorted-bin libc leak, top-chunk size corruption, and House of Force targeting `__malloc_hook` | Local solver uses the bundled loader/libc; remote mode accepts an authorized host and port |
| [Relic — Return to CSU](Relic-Return-to-CSU/README.md) | Three-stage `ret2csu` ROP chain, stack pivot, libc leak, and `system(command)` | Three-stage solver supports the bundled local runtime and authorized remote mode |
| [Stepper — Staged Shellcode](Stepper-Staged-Shellcode/README.md) | Restricted instruction sequences, persistent registers, and a staged payload written through the program's `read()` path into an RWX mapping | Solver checks the six-byte instruction limit and banned-byte list before connecting; supports local and authorized remote modes |

## Submission checklist

- Replace the division, team and author placeholders.
- Confirm which challenges were credited to the team before sending.
- Remove any challenge that was not credited.
- Review the organizer's attached template and transfer the relevant sections if required.
- Send the final Markdown file to the organizer using the subject line for the correct submission category.
