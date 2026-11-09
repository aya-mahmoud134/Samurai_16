#!/usr/bin/env python3
"""Invert the Lockbox validator without executing the supplied ELF."""

import argparse

KEY = bytes.fromhex("63 0e fa b0 e3 84 22 68")
CIPHERTEXT = bytes.fromhex(
    "93 e9 c7 87 90 48 03 30 "
    "89 d9 60 b5 b9 4a 45 33 "
    "46 08 b7 a6 40 3f 85 53 "
    "fb 4f 64 f1 cc db c5 44 "
    "7b 17 a3 2e 45 0a 08 b0 "
    "14 df 9f de"
)


def rol8(value: int, count: int) -> int:
    count %= 8
    return ((value << count) | (value >> (8 - count))) & 0xFF


def ror8(value: int, count: int) -> int:
    count %= 8
    return ((value >> count) | (value << (8 - count))) & 0xFF


def recover() -> bytes:
    state = 0x5B
    rotation = 1
    plaintext = bytearray()
    for index, encrypted_byte in enumerate(CIPHERTEXT):
        value = (encrypted_byte - KEY[index % len(KEY)]) & 0xFF
        value = ror8(value, rotation)
        plaintext.append(value ^ state)
        state = (state + index + encrypted_byte) & 0xFF
        rotation = (rotation + 3) % 8
    return bytes(plaintext)


def validate(candidate: bytes) -> bool:
    state = 0x5B
    rotation = 1
    transformed = bytearray()
    for index, plain_byte in enumerate(candidate):
        value = rol8(plain_byte ^ state, rotation)
        value = (value + KEY[index % len(KEY)]) & 0xFF
        transformed.append(value)
        state = (state + index + value) & 0xFF
        rotation = (rotation + 3) % 8
    return bytes(transformed) == CIPHERTEXT


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--show", action="store_true", help="print the recovered phrase")
    args = parser.parse_args()
    candidate = recover()
    assert len(candidate) == 44
    assert validate(candidate)
    assert candidate.startswith(b"CSCTF{") and candidate.endswith(b"}")
    print("PASS: recovered 44-byte phrase")
    print("PASS: forward transformation reproduces all 44 target bytes")
    print("PASS: expected flag syntax")
    if args.show:
        print(candidate.decode("ascii"))


if __name__ == "__main__":
    main()
