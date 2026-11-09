# Stepper — Restricted Instructions, Persistent Registers, Staged Shellcode

**Category:** Pwn / Shellcode  
**Architecture:** Linux x86-64  
**Status:** Local exploit validated; remote flag not verified

## Challenge summary

Stepper lets the player submit up to twelve tiny instruction sequences. Each step is limited to six bytes, and the bytes `0x0f`, `0x05`, `0x34`, and `0xcd` are rejected. At first glance this prevents direct use of `syscall` and `int` instructions.

The important implementation details are in `run_step()` and the guest trampoline:

- The guest register file is stored in the global `ctx` array and survives between steps.
- Each submitted instruction sequence is copied into an eight-byte slot at the start of a mapping created with `PROT_READ | PROT_WRITE | PROT_EXEC`.
- The trampoline at `code + 8` jumps indirectly through the pointer stored at `code + 14`, which is the runtime address of `guest_exit`.
- The byte filter is applied only to the short `chunk` read for each step.

The ELF is PIE with full RELRO and a non-executable stack; `main()` also has stack protection. The explicit anonymous RWX mapping is the important exception to the stack policy. The design therefore has two useful properties: registers persist across steps, and the program itself exposes a call path to `read()` that can write a larger second-stage payload into the RWX mapping.

Artifact hashes:

| Artifact | SHA-256 |
|---|---|
| `stepper` | `d3af02792c61b6f19dd37a6a9cc6e6f7fc5bb1891e78f47b621e92d7ff4f26fa` |
| `stepper.c` | `aed85083671dd9b30083e670563ae3166ff02b8364dd92d33cf0cf8edcbe534f` |

## 1. Capture a runtime code pointer

The first instruction is:

```asm
call next
```

The call pushes the address of the following instruction (`code + 5`) onto the guest stack. The second step executes `pop rbx`, preserving that address in `rbx`.

Because `rbx = code + 5`, the third step's:

```asm
mov rax, [rbx + 9]
```

reads the pointer at `code + 14`, which is the runtime `guest_exit` address written into the slot during setup. This avoids needing to guess the PIE base or the anonymous mapping address.

## 2. Derive `read@plt` and prepare its arguments

In the supplied binary, the static symbol offsets are:

```text
guest_exit = 0x1317
read@plt   = 0x1160
```

The next two steps subtract `0x1317` and add `0x1160` (implemented as subtraction of the two's-complement negative value). The resulting pointer is the runtime address of `read@plt`.

The remaining short steps preserve that address in `r12`, set `rdi = 0` for standard input, calculate `r13 = code + 0x80`, set `rsi = r13`, and set `rdx = 0x400`.

Step eleven executes:

```asm
call r12
```

This invokes `read(0, code + 0x80, 0x400)`. The exploit sends the second-stage bytes while the guest is blocked in that read.

## 3. Bypass the per-step filter with a second stage

The final three-byte step is:

```asm
jmp r13
```

It transfers execution to `code + 0x80`, where the unrestricted second-stage payload was written by the earlier `read()` call.

That payload is a compact `execve("/bin/sh", NULL, NULL)` shellcode sequence. It contains the `0x0f 0x05` syscall instruction, but it is not submitted through the six-byte step interface. The program's banned-byte loop only examines `chunk[]` before `run_step()`; it does not inspect the bytes subsequently copied by `read()` into the RWX mapping.

This is why the filter can be satisfied while the final payload still uses a syscall.

## 4. Solver and validation

The complete exploit is in [`solve.py`](solve.py). It checks every first-stage instruction against the six-byte limit and banned-byte list before connecting.

```bash
# Extract stepper.tar.gz into this directory first.
python3 solve.py --local

# Remote use: supply the challenge endpoint assigned to your team.
python3 solve.py --host HOST --port PORT
```

Local validation completed against the supplied binary. All eleven setup/read steps were accepted, the final jump reached the second-stage shellcode, and the shell printed `STEPPER_SHELL_SUCCESS` followed by `id` output. See [`local-validation.txt`](local-validation.txt) and [`evidence/local-validation.png`](evidence/local-validation.png).

**Remote status:** this run did not establish a connection to the remote service because DNS resolution was unavailable in the analysis environment. No remote flag is claimed or included here.

## AI methodology

- **Tool/model:** ChatGPT GPT-6 was used to help interpret the guest trampoline, plan the register-preserving instruction sequence, and draft the exploit automation.
- **Meaningful use:** the solver sends the twelve constrained steps, transfers the second-stage shellcode through the program's own `read()` call, and checks for a marker emitted by the spawned shell.
- **Human checks:** instruction lengths and banned bytes were programmatically checked; `guest_exit` and `read@plt` offsets were verified with `nm`/disassembly; the binary/source hashes were recorded; and the exploit was executed locally against the supplied binary.
- **Evidence:** `evidence/local-validation.png` is rendered from the saved output of the actual local run. The full transcript is preserved in `local-validation.txt`.

## Reproduction notes

The technique relies on this challenge's exact slot layout and trampoline. If the binary is rebuilt, re-check the `guest_exit` and `read@plt` offsets before using the exploit.
