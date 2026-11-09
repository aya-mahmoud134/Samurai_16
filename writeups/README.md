# CSCTF Writeup Index

**Division:** `[DIVISION]`  
**Team:** `[TEAM NAME]`  
**Authors:** `[TEAM MEMBERS]`

This index contains the Reverse Engineering challenges for which the analysis and local validation are complete. Each listed folder includes a human-readable explanation and a reproducible solver. Three genuine terminal workflow screenshots are collected in the team-level submission report. Literal flags, recovered keys, session nonces, session keys and live instance details are intentionally omitted.

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

## Additional local Pwn analysis

The repository also retains the Forge, Relic and Stepper Pwn folders. Their current evidence demonstrates local exploitation with the bundled runtime libraries. Remote challenge instances were not available during the last connection attempt, so these folders are not included in this submission-ready Reverse index and no remote flag is claimed.

## Submission checklist

- Replace the division, team and author placeholders.
- Confirm which challenges were credited to the team before sending.
- Remove any challenge that was not credited.
- Review the organizer's attached template and transfer the relevant sections if required.
- Send the final Markdown file to the organizer using the subject line for the correct submission category.
