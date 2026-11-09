# Relic — Three-Stage `ret2csu` and Stack Pivot

**Category:** Pwn / ROP  
**Architecture:** Linux x86-64  
**Runtime:** bundled glibc 2.31  
**Status:** Local exploit validated; remote flag not verified

## Challenge summary

The program contains one function, `vault()`, with a 64-byte stack buffer. It performs a single `read(0, buf, 0x120)`, so user input can overwrite the saved return address and the rest of the stack. The source is compiled without stack protection and without PIE. NX is enabled, so the solution uses ROP rather than executing stack data.

The binary is non-PIE, has full RELRO and a non-executable stack, and has no stack canary. Full RELRO does not prevent the exploit: the GOT is read for an information leak, not overwritten. The challenge includes a matching glibc 2.31 runtime.

Artifact hashes:

| Artifact | SHA-256 |
|---|---|
| `relic` | `ff001812d5eabb5dc1aac131ea9d0ea27889cf0fd29be683a7f164d56fed6de3` |
| `relic.c` | `b1866774d6d0452033706d33aecbf43660f1fefa6c1ae19c45e94b28da017ba2` |

## 1. Calculate the return-address offset

The vulnerable function reserves `0x40` bytes for `buf` and uses a normal frame pointer. The saved RBP occupies another eight bytes, so the saved RIP begins at:

```text
0x40 + 0x08 = 0x48 bytes
```

The exploit confirms this with a `0x48`-byte padding prefix before the first ROP gadget.

## 2. Stage one: read a second ROP chain into `.bss`

The binary contains the standard `__libc_csu_init` call sequence. The useful gadgets are:

| Address | Purpose |
|---|---|
| `0x4012da` | Pop `rbx`, `rbp`, `r12`–`r15`, then return |
| `0x4012c0` | Set `rdx`, `rsi`, `edi`, then call `[r15 + rbx*8]` |
| `0x401218` | `leave; ret` stack pivot |

The first chain sets the CSU registers so the indirect call invokes `read(0, BSS, 0x400)`. The cleanup sequence then returns through `leave; ret`, using the newly written `.bss` region as the next stack.

This avoids needing a conventional `pop rdi; pop rsi; pop rdx` gadget sequence.

## 3. Stage two: leak libc and receive stage three

The second chain uses the same CSU call gadget to invoke the resolved `write` function pointer from the GOT:

```text
write(1, GOT_READ, 8)
```

The eight-byte result is the runtime address of `read` inside libc. With the supplied glibc 2.31, the symbol offsets are:

| Symbol | Offset from libc base |
|---|---:|
| `read` | `0x10e1e0` |
| `system` | `0x52290` |

The solver calculates:

```text
libc_base = leaked_read - 0x10e1e0
system    = libc_base + 0x52290
```

The same stage then performs `read(0, BSS2, 0x400)` and pivots the stack to `BSS2`.

## 4. Stage three: call `system(command)`

The final chain stores a pointer to the calculated `system` address at `BSS2 + 0x98` and places the command string at `BSS2 + 0xa0`.

The CSU call gadget is configured with:

- `rdi = command_addr`
- `r15 = function_pointer_addr`
- `rbx = 0`, `rbp = 1`, so the indirect call executes once

It therefore calls `system(command)`. A single `ret` gadget is placed before the CSU sequence to maintain the expected stack alignment. The chain returns to `_exit@plt` after the command completes.

The command prints a unique `RELIC_ROP_SUCCESS` marker, runs `id`, and checks the conventional flag locations. The marker is used only to validate command execution; it is not a substitute for a recovered challenge flag.

## 5. Solver and validation

The complete three-stage exploit is in [`solve.py`](solve.py). It supports local execution through the challenge's bundled loader and libc, as well as remote execution when an authorized host and port are supplied.

```bash
# Extract relic.tar.gz into this directory first.
python3 solve.py --local

# Remote use: supply the challenge endpoint assigned to your team.
python3 solve.py --host HOST --port PORT
```

Local validation completed with the bundled glibc 2.31. The transcript showed the initial stack pivot, an eight-byte `read@libc` leak, the calculated libc base and `system` address, and the `RELIC_ROP_SUCCESS` marker followed by `id` output. See [`local-validation.txt`](local-validation.txt) and [`evidence/local-validation.png`](evidence/local-validation.png).

**Remote status:** this run did not establish a connection to the remote service because DNS resolution was unavailable in the analysis environment. No remote flag is claimed or included here.

## AI methodology

- **Tool/model:** ChatGPT GPT-6 was used to help map the vulnerable stack frame, interpret the CSU gadgets, and draft the staged ROP solver.
- **Meaningful use:** the script builds all three ROP stages, parses the libc leak, calculates the runtime `system` address, and checks for the final execution marker.
- **Human checks:** the vulnerable function and gadget addresses were verified in the supplied ELF disassembly; the GOT entries and libc symbol offsets were checked against the supplied binary and glibc 2.31; the binary/source hashes were recorded; and the exploit was run locally with the bundled loader and library.
- **Evidence:** `evidence/local-validation.png` is rendered from the saved output of the actual local run. The full transcript is in `local-validation.txt`.

## Reproduction notes

This exploit is specific to the supplied non-PIE binary and matching glibc 2.31. A different build may change the gadget addresses, GOT locations, or libc symbol offsets.
