# CSCTF Reverse Engineering — Meridian-Class Command-Authentication Unit Recovery

**Division:** `[DIVISION]`  
**Team:** `[TEAM NAME]`  
**Authors:** `[TEAM MEMBERS]`  
**Category:** Reverse Engineering

**Artifact:** `cau_verify` — Linux x86-64 ELF, 682,600 bytes  
**SHA-256:** `19fc211ceda00357c70c5039dd882f11491c8bfb092b15824bc13f2bdc84990c`

## 1. Objective and safety

The verifier accepts one 24-byte recovery key. The binary is self-contained, and the challenge explicitly allows static analysis. The supplied ELF was treated as untrusted data and was not executed.

The validator divides the input into three consecutive 8-byte blocks. Each block is processed by the same 64-bit mixing function and compared with one hard-coded 64-bit target.

## 2. Locate the validator and input constraints

Identify the artifact and inspect its headers:

```bash
file cau_verify
sha256sum cau_verify
readelf -h cau_verify
readelf -S cau_verify
```

The entry point transfers control to the main validation routine at `0x4014f0`. Static disassembly shows that the routine requires exactly one argument and checks that its length is `0x18` bytes.

The validator reads three little-endian 64-bit words at offsets `0`, `8`, and `16`. Each word is checked independently.

## 3. Reconstruct the mixing function

The same sequence of operations is applied to every block:

```text
x ^= x >> 33
x = x * A mod 2^64
x ^= x >> 33
x = x * B mod 2^64
x ^= x >> 33
```

The multipliers are odd:

```text
A = 0x9df50ad53e8f1c7b
B = 0xc17a4b92d6e30f55
```

The validator compares the three results against constants embedded in the executable:

| Input block | Target |
|---|---|
| bytes 0–7 | `0xd8dba78e270f595d` |
| bytes 8–15 | `0x25d4e9834acb3349` |
| bytes 16–23 | `0x976a0bc7e24f7338` |

All arithmetic is unsigned 64-bit arithmetic, so multiplication wraps modulo `2^64`.

## 4. Why the function is invertible

The operation `x ^= x >> 33` is self-inverse for 64-bit values. Applying it twice cancels the shifted contribution because shifting by 66 bits leaves no bits.

Both multipliers are odd, so each has a multiplicative inverse modulo `2^64`. Python calculates those inverses with:

```python
pow(A, -1, 1 << 64)
pow(B, -1, 1 << 64)
```

The inverse therefore applies the operations in reverse order:

1. Undo the final XOR-shift.
2. Multiply by the modular inverse of `B`.
3. Undo the middle XOR-shift.
4. Multiply by the modular inverse of `A`.
5. Undo the first XOR-shift.

This recovers each original 64-bit word exactly. The three recovered words are converted back to little-endian bytes and concatenated.

## 5. Reproducible solver

Run the verification-only mode:

```bash
python3 solve.py
```

The solver inverts all three targets, re-applies the original forward function to each recovered block, and checks the total input length and ASCII encoding. It does not print the recovery key by default.

To display the recovered value locally:

```bash
python3 solve.py --show
```

## 6. Validation

- The artifact SHA-256 matches the challenge-provided digest.
- The disassembly confirms the 24-byte length check and the three block offsets.
- Each recovered 64-bit block reproduces its corresponding embedded target under the original forward function.
- The concatenated result is exactly 24 ASCII bytes.
- No executable code from the supplied ELF was run.

## AI-assisted methodology
The tool/model, meaningful automation, human checks and genuine workflow screenshots for this challenge are documented in the [consolidated team writeup](../CSCTF-Participant-Writeup.md#ai-assisted-methodology).

## Workflow evidence
See the three genuine terminal workflow screenshots in the [consolidated team writeup](../CSCTF-Participant-Writeup.md#workflow-screenshots).
