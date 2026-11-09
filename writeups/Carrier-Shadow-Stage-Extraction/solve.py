#!/usr/bin/env python3
"""Statically extract the embedded second-stage ELF from carrier-shadow."""

from __future__ import annotations

import argparse
import hashlib
import struct
import zlib
from collections import Counter
from pathlib import Path

EXPECTED_INPUT_SHA256 = "995fd7161d984898e521eb581f93380b11f31e3de342b368519a2221fb192a04"
EXPECTED_STAGE_SHA256 = "4f864208546b2108ae453292220e297684fe6bb74384e380c95dd9b4b33b06b9"
EH_FRAME_HDR_OFFSET = 0x9B600
HUFFMAN_TABLE_POINTERS_OFFSET = 0x145810
SIGNATURE_INDEX = 123
PRNG_SEED = 0x6A2B3C4D


def decode_carrier(data: bytes) -> bytes:
    if hashlib.sha256(data).hexdigest() != EXPECTED_INPUT_SHA256:
        raise ValueError("carrier-shadow SHA-256 mismatch")
    print(f"input SHA-256 OK: {EXPECTED_INPUT_SHA256}")

    h = EH_FRAME_HDR_OFFSET
    count = struct.unpack_from("<I", data, h + 8)[0]
    starts = [h + struct.unpack_from("<i", data, h + 12 + i * 8)[0] for i in range(count)]
    deltas = [right - left for left, right in zip(starts, starts[1:])]
    k = SIGNATURE_INDEX
    signature = deltas[k:k + 16]
    if len(signature) != 16:
        raise ValueError("Function-address table is shorter than expected")
    selector = deltas[k + 8] - 2
    compressed_size = sum((deltas[k + 9 + j] - 2) << (8 * j) for j in range(4))
    expected_xor = deltas[k + 13] - 2
    if selector < 0 or compressed_size <= 0:
        raise ValueError("Invalid embedded payload descriptor")
    print(f".eh_frame_hdr entries={count}; payload descriptor at delta index {k}")
    print(f"descriptor={signature}; table selector={selector}; encoded size={compressed_size}; XOR check=0x{expected_xor:02x}")

    pointer = struct.unpack_from("<Q", data, HUFFMAN_TABLE_POINTERS_OFFSET + selector * 8)[0]
    lengths = data[pointer:pointer + 256]
    if len(lengths) != 256 or not any(lengths):
        raise ValueError("Invalid canonical Huffman length table")

    counts = Counter(lengths)
    first_code: dict[int, int] = {}
    code = 0
    for bit_length in range(1, max(lengths) + 1):
        first_code[bit_length] = code
        code = (code + counts[bit_length]) << 1

    symbol_codes: dict[int, tuple[int, int]] = {}
    seen: Counter[int] = Counter()
    for symbol, bit_length in enumerate(lengths):
        if bit_length:
            symbol_codes[symbol] = (first_code[bit_length] + seen[bit_length], bit_length)
            seen[bit_length] += 1

    encoded = bytearray()
    accumulator = 0
    bit_count = 0
    last_index = None
    for index in range(k + 14, len(deltas)):
        symbol = deltas[index] - 2
        if symbol not in symbol_codes:
            raise ValueError(f"Unknown Huffman symbol {symbol} at delta index {index}")
        word, bit_length = symbol_codes[symbol]
        for shift in range(bit_length - 1, -1, -1):
            accumulator = (accumulator << 1) | ((word >> shift) & 1)
            bit_count += 1
            if bit_count == 8:
                encoded.append(accumulator)
                accumulator = 0
                bit_count = 0
                if len(encoded) == compressed_size:
                    last_index = index
                    break
        if len(encoded) == compressed_size:
            break

    if len(encoded) != compressed_size:
        raise ValueError(f"Decoded {len(encoded)} of {compressed_size} encoded bytes")
    checksum = 0
    for value in encoded:
        checksum ^= value
    if checksum != expected_xor:
        raise ValueError(f"Encoded-stream XOR check failed: {checksum:#x} != {expected_xor:#x}")
    print(f"canonical Huffman decoded {len(encoded)} bytes (through delta {last_index}); XOR check PASS")

    x = PRNG_SEED
    for index in range(len(encoded)):
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= x >> 17
        x ^= (x << 5) & 0xFFFFFFFF
        x &= 0xFFFFFFFF
        encoded[index] ^= x & 0xFF

    stage = zlib.decompress(bytes(encoded), -15)
    if not stage.startswith(b"\x7fELF"):
        raise ValueError("Decompressed stage does not have an ELF header")
    stage_hash = hashlib.sha256(stage).hexdigest()
    if stage_hash != EXPECTED_STAGE_SHA256:
        raise ValueError(f"Second-stage SHA-256 mismatch: {stage_hash}")
    print(f"xorshift32 stream + raw DEFLATE -> {len(stage)}-byte ELF")
    print(f"second-stage SHA-256 OK: {stage_hash}")
    return stage


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("carrier", nargs="?", default="carrier-shadow")
    parser.add_argument("-o", "--output", default="carrier-stage2.elf")
    parser.add_argument("--show", action="store_true", help="print the embedded flag string")
    args = parser.parse_args()

    stage = decode_carrier(Path(args.carrier).read_bytes())
    Path(args.output).write_bytes(stage)
    marker = b"payload: operation-dawn authorization"
    flag_offset = stage.find(b"CSCTF{")
    marker_offset = stage.find(marker)
    if flag_offset < 0 or marker_offset < 0:
        raise ValueError("Expected authorization marker was not found in the extracted ELF")
    print(f"wrote {args.output}; authorization marker at file offset 0x{marker_offset:x}")
    print(f"flag-format string found at file offset 0x{flag_offset:x}; payload was not executed")
    if args.show:
        end = stage.find(b"\0", flag_offset)
        print(stage[flag_offset:end].decode("ascii"))


if __name__ == "__main__":
    main()
