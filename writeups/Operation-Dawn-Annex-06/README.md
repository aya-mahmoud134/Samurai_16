# CSCTF — Operation Dawn, Annex Entry 06: Lockbox

**Category:** Reverse Engineering  
**Architecture:** Linux ELF, x86-64  
**Flag:** `CSCTF{06_ash_hawk_road_at_garrisoned_38318f}`

## 1. Challenge overview

We are given a small Linux executable named `lockbox`. It accepts commands such as `status`, `log`, and `open`, but the accepted passphrase is not exposed directly.

Start by identifying the file:

```bash
file lockbox
```

The result identifies a stripped, dynamically linked, 64-bit x86-64 ELF executable. The supplied sample has SHA-256 `f4e6bc8ccbcef3908467a41941fbc7f561adab7e45a2bbfa61c7b78c07c724c4`.

## 2. Static reconnaissance

List the printable strings:

```bash
strings -a -t x lockbox
```

Some useful strings appear in `.rodata`:

```text
open: supply a pass phrase
ASH ARMY GATE LOCK  model 43-K  (field unit, north canal)
GATE: pass phrase accepted - crossing open
GATE: pass phrase refused - crossing barred
the quartermaster laughs - that is last week's code, soldier
4+>5{(>(:6>{:5?{625?{/3>{/)2+,2)>
```

The final encoded-looking string is a clue, but it is not the real passphrase. It belongs to a decoy check handled by the command-processing function.

## 3. Find the hidden validator

Inspect the ELF initialization array:

```bash
readelf -x .init_array lockbox
```

It contains pointers to initialization routines, including the routine at `0x10e0`. This routine runs before `main()` and is responsible for validating the real passphrase supplied as the third process argument.

Disassemble the executable:

```bash
objdump -d -M intel lockbox
```

At `0x10e0`, the routine:

1. Checks that at least three command-line arguments are present.
2. Checks that `argv[1]` is the string `open`.
3. Copies and trims `argv[2]`.
4. Requires the passphrase length to equal `0x2c` (44 bytes).
5. Transforms each input byte and compares it with an encrypted byte array.
6. Sets the global gate-state variable at `0x4014` to `0x5a` only if every byte matches.

The normal command handler is at `0x11c0`. It later checks the global value at `0x4014` to decide whether to print the accepted or refused message.

## 4. Recover the byte transformation

The important part of the validator's loop is:

```asm
movzx edx, BYTE PTR [rbx+rax]
mov    r8, rax
and    r8d, 7
xor    edx, esi
rol    dl, cl
add    dl, BYTE PTR [r11+r8]
cmp    dl, BYTE PTR [r10+rax]

add    esi, eax
add    rax, 1
add    ecx, 3
add    esi, edx
```

The loop uses:

- Initial state: `0x5b`
- Initial rotation: `1`
- An 8-byte key, indexed with `i % 8`
- Rotation increment: `3`
- A 44-byte encrypted target

For each byte, the low-byte transformation is:

```text
cipher[i] = (ROL8(plain[i] XOR state, rotation) + key[i % 8]) mod 256
```

The state update in the assembly adds the index and the transformed `edx` value. Only the low byte of the state is needed to reverse the next input byte. Since the low byte of `edx` after the `rol` and `add` instructions is the current ciphertext byte, the low-byte state update is:

```text
state = (state + i + cipher[i]) mod 256
```

Therefore, invert the transformation in reverse order:

```text
plain[i] = ROR8((cipher[i] - key[i % 8]) mod 256, rotation) XOR state
```

## 5. Extract the key and encrypted bytes

The validator references the key at virtual address `0x224d` and the encrypted target at `0x2255`.

You can inspect the bytes with:

```bash
objdump -s -j .rodata lockbox
```

Key (8 bytes):

```text
63 0e fa b0 e3 84 22 68
```

Encrypted target (44 bytes):

```text
93 e9 c7 87 90 48 03 30
89 d9 60 b5 b9 4a 45 33
46 08 b7 a6 40 3f 85 53
fb 4f 64 f1 cc db c5 44
7b 17 a3 2e 45 0a 08 b0
14 df 9f de
```

## 6. Python decoder

The following script reverses the byte transformation and prints the accepted passphrase:

```python
key = bytes.fromhex(
    "63 0e fa b0 e3 84 22 68"
)

ciphertext = bytes.fromhex(
    "93 e9 c7 87 90 48 03 30 "
    "89 d9 60 b5 b9 4a 45 33 "
    "46 08 b7 a6 40 3f 85 53 "
    "fb 4f 64 f1 cc db c5 44 "
    "7b 17 a3 2e 45 0a 08 b0 "
    "14 df 9f de"
)

def ror8(value, count):
    count %= 8
    if count == 0:
        return value
    return ((value >> count) | (value << (8 - count))) & 0xff

state = 0x5b
rotation = 1
plaintext = bytearray()

for i, encrypted_byte in enumerate(ciphertext):
    value = (encrypted_byte - key[i % 8]) & 0xff
    value = ror8(value, rotation)
    plaintext.append(value ^ state)

    state = (state + i + encrypted_byte) & 0xff
    rotation = (rotation + 3) % 8

print(plaintext.decode())
```

Output:

```text
CSCTF{06_ash_hawk_road_at_garrisoned_38318f}
```

## 7. Verify against the original executable

Run the original program with the recovered phrase:

```bash
chmod +x lockbox
./lockbox open 'CSCTF{06_ash_hawk_road_at_garrisoned_38318f}'
```

Expected output:

```text
GATE: pass phrase accepted - crossing open
```

The decoy phrase can also be tested:

```bash
./lockbox open 'open sesame and mind the tripwire'
```

It prints the quartermaster's decoy message and then refuses the gate. This confirms that the visible XOR string is not the accepted passphrase.

## 8. Flag

```text
CSCTF{06_ash_hawk_road_at_garrisoned_38318f}
```
