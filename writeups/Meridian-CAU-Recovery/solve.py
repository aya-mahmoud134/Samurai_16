#!/usr/bin/env python3
"""Recover the 24-byte CAU key by inverting its 64-bit block hash."""

import argparse

MASK64 = (1 << 64) - 1
MODULUS = 1 << 64
MULTIPLIER_A = 0x9DF50AD53E8F1C7B
MULTIPLIER_B = 0xC17A4B92D6E30F55
TARGETS = (
    0xD8DBA78E270F595D,
    0x25D4E9834ACB3349,
    0x976A0BC7E24F7338,
)


def xor_shift_right_33(value: int) -> int:
    return (value ^ (value >> 33)) & MASK64


def hash_block(value: int) -> int:
    value = xor_shift_right_33(value)
    value = (value * MULTIPLIER_A) & MASK64
    value = xor_shift_right_33(value)
    value = (value * MULTIPLIER_B) & MASK64
    return xor_shift_right_33(value)


def recover_block(target: int) -> bytes:
    value = xor_shift_right_33(target)
    value = (value * pow(MULTIPLIER_B, -1, MODULUS)) & MASK64
    value = xor_shift_right_33(value)
    value = (value * pow(MULTIPLIER_A, -1, MODULUS)) & MASK64
    value = xor_shift_right_33(value)
    return value.to_bytes(8, "little")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--show", action="store_true", help="print the recovered 24-byte key")
    args = parser.parse_args()
    blocks = [recover_block(target) for target in TARGETS]
    for block, target in zip(blocks, TARGETS):
        assert hash_block(int.from_bytes(block, "little")) == target
    key = b"".join(blocks)
    assert len(key) == 24
    key.decode("ascii")
    print("PASS: all three recovered 64-bit blocks match their embedded targets")
    print("PASS: concatenated input is exactly 24 ASCII bytes")
    if args.show:
        print(key.decode("ascii"))


if __name__ == "__main__":
    main()
