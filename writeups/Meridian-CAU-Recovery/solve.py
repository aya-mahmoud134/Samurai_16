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
    """Apply x ^= x >> 33 in 64-bit arithmetic."""
    return (value ^ (value >> 33)) & MASK64


def inverse_xor_shift_right_33(value: int) -> int:
    """Invert x ^= x >> 33; one XOR is enough because 2*33 >= 64."""
    return (value ^ (value >> 33)) & MASK64


def hash_block(value: int) -> int:
    """Reproduce the validator's 64-bit mixing routine."""
    value = xor_shift_right_33(value)
    value = (value * MULTIPLIER_A) & MASK64
    value = xor_shift_right_33(value)
    value = (value * MULTIPLIER_B) & MASK64
    value = xor_shift_right_33(value)
    return value


def recover_block(target: int) -> bytes:
    """Invert the validator hash and return the original 8 input bytes."""
    value = inverse_xor_shift_right_33(target)
    value = (value * pow(MULTIPLIER_B, -1, MODULUS)) & MASK64
    value = inverse_xor_shift_right_33(value)
    value = (value * pow(MULTIPLIER_A, -1, MODULUS)) & MASK64
    value = inverse_xor_shift_right_33(value)
    return value.to_bytes(8, byteorder="little")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--verify",
        action="store_true",
        help="verify all recovered blocks without printing the key",
    )
    args = parser.parse_args()

    blocks = [recover_block(target) for target in TARGETS]

    for block, target in zip(blocks, TARGETS):
        recovered_integer = int.from_bytes(block, byteorder="little")
        assert hash_block(recovered_integer) == target

    key = b"".join(blocks)
    assert len(key) == 24
    decoded_key = key.decode("ascii")

    if args.verify:
        print("PASS: all 3 recovered 64-bit blocks match their target hashes")
        print("PASS: recovered input length is exactly 24 bytes")
        print("PASS: all recovered bytes are ASCII")
    else:
        print(decoded_key)


if __name__ == "__main__":
    main()
