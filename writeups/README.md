# CSCTF Reverse Engineering — Writeup Index

**Division:** `[DIVISION]`  
**Team:** `[TEAM NAME]`  
**Authors:** `[TEAM MEMBERS]`

This folder contains completed, statically reproducible Reverse Engineering writeups. Each challenge folder includes a human-readable explanation, a Python solver, and a terminal workflow screenshot. The writeups intentionally omit literal flags in accordance with the event's submission guidance.

## Completed writeups

| Challenge | Main technique | Validation |
|---|---|---|
| [Dawn Control Firmware Recovery](Dawn-Firmware-Recovery/README.md) | Custom record container, CRC-32, preset-dictionary DEFLATE, CPIO, U-Boot redundant environment, repeating-key XOR | Input hash, four record CRCs, two environment CRCs, 30-byte syntax check |
| [PoshTerm Hidden Service Code](PoshTerm-Service-Code/README.md) | Embedded JavaScript analysis, hidden command discovery, MD5 guards, Julian-date key derivation, RC4 | PE hash, argument MD5, independently computed Julian date, 48-byte plaintext syntax check |
| [Carrier Shadow Stage Extraction](Carrier-Shadow-Stage-Extraction/README.md) | `.eh_frame_hdr` address-delta decoding, canonical Huffman, xorshift32, raw DEFLATE | Input hash, descriptor checksum, extracted ELF hash, authorization marker |

Previously published writeups in the repository:

- [Operation Dawn — Annex Entry 06: Lockbox](Operation-Dawn-Annex-06/README.md)
- [Meridian-Class CAU Recovery](Meridian-CAU-Recovery/README.md)

## Submission note

Fill in the division, team name and author fields before sending the Markdown files to the organizers. Unsolved or unverified challenges are deliberately not represented as completed writeups.
