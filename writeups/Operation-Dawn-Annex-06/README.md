# CSCTF Reverse Engineering — Operation Dawn, Annex Entry 06: Lockbox

**Division:** `[DIVISION]`  
**Team:** `[TEAM NAME]`  
**Authors:** `[TEAM MEMBERS]`  
**Category:** Reverse Engineering

**Artifact:** `lockbox` — Linux x86-64 ELF  
**SHA-256:** `f4e6bc8ccbcef3908467a41941fbc7f561adab7e45a2bbfa61c7b78c07c724c4`

## 1. Objective and handling

The field unit accepts a 44-byte passphrase, but the executable does not reveal it. The goal is to recover the accepted input from the validator's static data and transformation.

The ELF was inspected as untrusted data. The supplied executable was not launched during this analysis; the recovered input was validated by reproducing the validator's forward transformation in Python.

## 2. Separate the decoy from the real check

A first pass with `strings -a -t x lockbox` reveals the gate messages and an encoded-looking phrase:

```text
open: supply a pass phrase
GATE: pass phrase accepted - crossing open
GATE: pass phrase refused - crossing barred
the quartermaster laughs - that is last week's code, soldier
4+>5{(>(:6>{:5?{625?{/3>{/)2+,2)>
```

The visible encoded phrase belongs to a decoy path in the normal command handler. The actual passphrase check is performed earlier, from an ELF initialization routine.

## 3. Locate the pre-main validator

Inspect `.init_array` and disassemble the ELF:

```bash
readelf -x .init_array lockbox
objdump -d -M intel lockbox
```

The initialization entry at `0x10e0` validates the supplied command-line arguments before the ordinary command handler at `0x11c0` runs.

The routine checks that the command is `open`, trims the supplied phrase, and requires a length of `0x2c` bytes. It then transforms the input byte-by-byte and compares each result with a 44-byte target array. A successful comparison sets the gate-state value later checked by the normal handler.

This explains why following only the obvious `main()` command path leads to the decoy.

## 4. Reconstruct the byte transformation

The validator's loop performs these operations on each byte:

```text
value = plaintext[i] XOR state
value = ROL8(value, rotation)
value = (value + key[i mod 8]) mod 256
compare value with target[i]
state = (state + i + value) mod 256
rotation = rotation + 3
```

The initial state is `0x5b`, the initial rotation is `1`, and the 8-byte key is stored in `.rodata`. The rotation is applied modulo eight by the 8-bit rotate instruction.

The transformation is reversible because each operation has a direct inverse:

- Subtract the corresponding key byte modulo 256.
- Rotate right by the same count.
- XOR with the current state.

The state for the next byte is updated from the current index and the encrypted byte. No brute force is needed.

## 5. Recover and independently validate the input

The included `solve.py` reverses the 44 target bytes. It then applies the original forward transformation to the recovered bytes and asserts that every output byte matches the target array.

Run:

```bash
python3 solve.py
```

The default mode reports only validation results. To display the recovered phrase locally, use:

```bash
python3 solve.py --show
```

The solver checks the exact length, the expected flag wrapper syntax, and the complete forward-transform equality. It does not execute the ELF.

## 6. Validation

The following checks passed:

- The supplied artifact hash matches the recorded SHA-256.
- Static analysis identifies the pre-main validator and the 44-byte length check.
- The recovered input has exactly 44 bytes.
- The Python forward transformation reproduces all 44 target bytes.
- The recovered bytes satisfy the expected `CSCTF{...}` wrapper.
- The decoy phrase is not used as the accepted passphrase.

The result is therefore supported by a byte-for-byte inverse and forward check, rather than by a guessed phrase or an execution of the untrusted binary.

## AI-assisted methodology
The tool/model, meaningful automation, human checks and genuine workflow screenshots for this challenge are documented in the [consolidated team writeup](../CSCTF-Participant-Writeup.md#ai-assisted-methodology).

## Workflow evidence
See the three genuine terminal workflow screenshots in the [consolidated team writeup](../CSCTF-Participant-Writeup.md#workflow-screenshots).
