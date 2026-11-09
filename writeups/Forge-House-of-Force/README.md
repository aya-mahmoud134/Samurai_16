# Forge — House of Force Through `temper()`

**Category:** Pwn / Heap Exploitation  
**Architecture:** Linux x86-64  
**Runtime:** bundled glibc 2.27  
**Status:** Local exploit validated; remote flag not verified

## Challenge summary

The program is a small note manager. Each note stores a heap pointer and the requested allocation size. The important operations are `forge` (allocate), `temper` (append), `inspect` (print), and `melt` (free).

The source makes the vulnerability explicit:

```c
read_until_nl(p + strlen(p), notes[i].size);
```

`temper()` starts writing at the end of the current C string, but passes the *entire allocation size* instead of the remaining capacity. If the string is already almost as long as the allocation, the append can overwrite the next heap chunk's metadata.

The supplied binary is PIE with full RELRO, a non-executable stack, and stack protection. Those protections do not stop this heap metadata corruption. The bundled glibc is 2.27, which is important because safe-linking is not enabled and the malloc hooks still exist.

Artifact hashes:

| Artifact | SHA-256 |
|---|---|
| `forge` | `e3cd5cbbe1eb25b50184a41a14f249867d1415f6b1317ce43cab131998481a66` |
| `forge.c` | `b3d105c173737afbf2edab7d0c7865016955679de4c69b24d76d6d8e3553dd51` |

## 1. Obtain a heap pointer from tcache

Allocate two `0x70` notes, then free them in order 0 and 1. Reallocate one `0x70` note. In glibc 2.27, the freed tcache entry stores its forward pointer directly in the user-data area; there is no safe-linking XOR to undo.

`inspect(0)` therefore prints the stale `fd` pointer, which points to the other freed chunk. The solver decodes this little-endian value as the heap chunk pointer used to calculate the later top-chunk location.

## 2. Obtain the libc base from the unsorted bin

Next allocate a `0x500` note and a small guard note after it. Free the large note and allocate the same size again. Since this size is larger than the tcache range in the supplied glibc, the freed chunk passes through the unsorted bin.

The first words of the returned chunk contain the unsorted-bin `fd` pointer into `main_arena`. For this exact bundled libc, the leaked pointer is at offset `0x3ebca0` from the libc base:

```text
libc_base = unsorted_bin_fd - 0x3ebca0
```

The solver accounts for `puts()` stopping when a pointer byte equals newline. A four-byte leak prefix is reconstructed only in the specific canonical-pointer case where the next byte is `0x0a` and the following byte is `0x7f`; shorter or ambiguous leaks are rejected rather than guessed.

## 3. Corrupt the top-chunk size

Allocate a note with request size `0x18` and fill the first 23 bytes, followed by a NUL byte. On this allocator, the request is served by a `0x20`-byte chunk. Its user pointer is immediately followed by the next chunk header's `prev_size` and `size` fields.

Because the string length is `0x17`, `temper()` begins at `p + 0x17`. Sending:

```python
b"T" + b"\xff" * 8
```

places the first byte at the final byte before the next header and the eight `0xff` bytes over the top chunk's size field. The top size becomes `0xffffffffffffffff`.

This is the key bug: the append operation is bounded by `notes[i].size`, not by `notes[i].size - strlen(p)`.

## 4. Apply House of Force to `__malloc_hook`

With the top chunk size corrupted to a very large value, a carefully calculated allocation advances the top chunk to the area immediately before `__malloc_hook`.

The bundled glibc 2.27 symbols used by the exploit are:

| Symbol | Offset from libc base |
|---|---:|
| `__malloc_hook` | `0x3ebc30` |
| `system` | `0x4f420` |
| `/bin/sh\0` | `0x1b3d88` |
| unsorted-bin fd leak | `0x3ebca0` |

The large request is calculated from the leaked heap and libc addresses. A following `malloc(0x10)` returns a pointer to `__malloc_hook`, and the allocation content overwrites that hook with the address of `system`.

Finally, another allocation is requested with a size equal to the address of the `/bin/sh` string in the same libc. The allocator invokes `__malloc_hook(size, ...)`; because the hook now points to `system`, this becomes `system("/bin/sh")` and gives command execution.

## 5. Solver and validation

The complete exploit is in [`solve.py`](solve.py). It supports local testing with the exact bundled loader/libc and a remote mode that takes an authorized host and port as command-line arguments.

```bash
# Extract the supplied forge archive into this directory first.
python3 solve.py --local

# Remote use: supply the challenge endpoint assigned to your team.
python3 solve.py --host HOST --port PORT
```

Local validation completed against the supplied binary and glibc 2.27. The transcript showed a heap leak, an unsorted-bin/libc leak, the `__malloc_hook` overwrite, and the marker `FORGE_SHELL_SUCCESS` followed by `id` output. See [`local-validation.txt`](local-validation.txt) and [`evidence/local-validation.png`](evidence/local-validation.png).

**Remote validation (2026-11-09):** The latest recorded target is `w01.ctf.chronos-security.ro:33121`. This environment could not resolve the hostname (`Temporary failure in name resolution`), so no TCP connection or remote exploit run was possible. No verified current IPv4 address for `w01` was available, and no remote flag is claimed. Re-run the solver once the assigned instance is live and its endpoint resolves.

## AI methodology

- **Tool/model:** ChatGPT GPT-6 was used to help trace the source-level overflow, reason about the glibc 2.27 heap layout, and draft the reproducible exploit script.
- **Meaningful use:** the script automates the tcache leak, unsorted-bin leak, top-size corruption, House of Force allocation, and malloc-hook trigger. It also checks the final shell marker rather than treating a successful connection as proof.
- **Human checks:** the source and ELF were inspected independently; symbol offsets were checked against the bundled `libc.so.6`; the binary and source SHA-256 values were recorded; and the final exploit was run locally with the bundled loader and library.
- **Evidence:** the terminal capture in `evidence/local-validation.png` is rendered from the saved output of the actual local run. The full text output is preserved in `local-validation.txt`.

## Reproduction notes

The solver assumes the supplied challenge build and matching glibc 2.27. Do not substitute the host system's libc: the hook offsets and `/bin/sh` offset are version-specific.
