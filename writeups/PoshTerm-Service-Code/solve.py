#!/usr/bin/env python3
"""Recover the hidden PoshTerm service payload without executing the PE."""

from __future__ import annotations

import argparse
import hashlib
import re
from datetime import date
from pathlib import Path

EXPECTED_EXE_SHA256 = "a20d559ea90c7f64241314863c4ee194f8dc1467d42eaf6211c43de7f530f135"
CIPHERTEXT = bytes.fromhex(
    "37f1f43867e61d207c0b78ca4385ee14"
    "f67d98e0c0cdbe6e5027ff506e302cb6"
    "6b8c8c5ad07d726c0e24e9f13bbcdfa9"
)
AIRCRAFT = "Cessna 421 Golden Eagle"
FIRST_FLIGHT = date(1965, 10, 14)


def julian_date_midnight(day: date) -> str:
    a = (14 - day.month) // 12
    y = day.year + 4800 - a
    m = day.month + 12 * a - 3
    jdn = day.day + (153 * m + 2) // 5 + 365 * y + y // 4 - y // 100 + y // 400 - 32045
    return f"{jdn - 0.5:.7f}"


def rc4(key: bytes, ciphertext: bytes) -> bytes:
    if not key:
        raise ValueError("RC4 key cannot be empty")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]

    output = bytearray()
    i = j = 0
    for value in ciphertext:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output.append(value ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(output)


def recover(executable: Path, show: bool = False) -> bytes:
    data = executable.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_EXE_SHA256:
        raise ValueError(f"PoshTerm.exe SHA-256 mismatch: {digest}")
    print(f"PoshTerm.exe SHA-256 OK: {digest}")

    required_markers = [b"service_code", b"POSHTERM_PROFILE", b"createHash(\"md5\")", b"first_flight"]
    for marker in required_markers:
        if marker not in data:
            raise ValueError(f"Expected static marker missing: {marker!r}")
    print("hidden command, environment guard, MD5 checks, and first-flight lookup found")

    expected_code_md5 = hashlib.md5(AIRCRAFT.encode("utf-8")).hexdigest()
    if expected_code_md5 != "e3db766fd63bf1afdd34abcac1f5c112":
        raise ValueError("Aircraft argument does not match the embedded MD5 constant")
    print(f"aircraft argument MD5 matches embedded constant: {expected_code_md5}")

    jd = julian_date_midnight(FIRST_FLIGHT)
    if jd != "2439047.5000000":
        raise ValueError(f"Unexpected Julian date: {jd}")
    plaintext = rc4(jd.encode("ascii"), CIPHERTEXT)
    if not re.fullmatch(rb"CSCTF\{[A-Za-z0-9_]+\}", plaintext):
        raise ValueError("RC4 output does not match the expected flag syntax")
    print(f"first flight {FIRST_FLIGHT.isoformat()} -> Julian date {jd}")
    print(f"RC4 decrypted {len(plaintext)} bytes; syntax check PASS; SHA-256={hashlib.sha256(plaintext).hexdigest()}")
    print("the environment gate was not bypassed by running the PE; the embedded transform was reproduced offline")
    if show:
        print(plaintext.decode("ascii"))
    return plaintext


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", nargs="?", default="PoshTerm.exe")
    parser.add_argument("--show", action="store_true", help="print the recovered plaintext")
    args = parser.parse_args()
    recover(Path(args.executable), args.show)


if __name__ == "__main__":
    main()
