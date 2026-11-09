#!/usr/bin/env python3

key = bytes.fromhex("63 0e fa b0 e3 84 22 68")
ciphertext = bytes.fromhex(
    "93 e9 c7 87 90 48 03 30 "
    "89 d9 60 b5 b9 4a 45 33 "
    "46 08 b7 a6 40 3f 85 53 "
    "fb 4f 64 f1 cc db c5 44 "
    "7b 17 a3 2e 45 0a 08 b0 "
    "14 df 9f de"
)


def ror8(value: int, count: int) -> int:
    count %= 8
    if count == 0:
        return value
    return ((value >> count) | (value << (8 - count))) & 0xff


state = 0x5b
rotation = 1
plaintext = bytearray()

for index, encrypted_byte in enumerate(ciphertext):
    value = (encrypted_byte - key[index % len(key)]) & 0xff
    value = ror8(value, rotation)
    plaintext.append(value ^ state)

    state = (state + index + encrypted_byte) & 0xff
    rotation = (rotation + 3) % 8

print(plaintext.decode())
