#!/usr/bin/env python3
"""Statically recover the admin token from the DWF-W firmware container."""

from __future__ import annotations

import argparse
import hashlib
import re
import struct
import zlib
from pathlib import Path

EXPECTED_SHA256 = "ae253e80cfca3035fe1e882c3c26a75b1d701f1b1bb343ba290d590573bc4313"
MAGIC = b"DWFW"


def parse_container(data: bytes) -> dict[str, bytes]:
    if len(data) != 1_048_576:
        raise ValueError(f"Unexpected firmware size: {len(data)}")
    if data[:4] != MAGIC:
        raise ValueError("Bad DWF-W magic")

    version, count = struct.unpack_from("<HH", data, 4)
    if version != 1 or count != 4:
        raise ValueError(f"Unsupported container header: version={version}, records={count}")

    records: dict[str, bytes] = {}
    for index in range(count):
        offset = 8 + index * 20
        name = data[offset:offset + 8].split(b"\0", 1)[0].decode("ascii")
        start, size, stored_crc = struct.unpack_from("<III", data, offset + 8)
        end = start + size
        if end > len(data):
            raise ValueError(f"Record {name} extends beyond the firmware image")
        payload = data[start:end]
        actual_crc = zlib.crc32(payload) & 0xFFFFFFFF
        if actual_crc != stored_crc:
            raise ValueError(f"CRC mismatch in {name}: {stored_crc:08x} != {actual_crc:08x}")
        records[name] = payload
        print(f"record {name:<8} offset=0x{start:04x} size={size:<5} CRC32 OK")

    required = {"loader", "ubootenv", "msgcat", "rootfs"}
    if set(records) != required:
        raise ValueError(f"Unexpected record set: {sorted(records)}")
    return records


def extract_newc(blob: bytes) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    cursor = 0
    while cursor + 110 <= len(blob):
        header = blob[cursor:cursor + 110]
        if header[:6] not in (b"070701", b"070702"):
            raise ValueError(f"Invalid newc CPIO header at 0x{cursor:x}")
        fields = [int(header[i:i + 8], 16) for i in range(6, 110, 8)]
        file_size = fields[6]
        name_size = fields[11]
        name_start = cursor + 110
        name_end = name_start + name_size
        name = blob[name_start:name_end - 1].decode("utf-8", "strict")
        data_start = (name_end + 3) & ~3
        data_end = data_start + file_size
        if data_end > len(blob):
            raise ValueError(f"CPIO entry {name} exceeds archive bounds")
        if name == "TRAILER!!!":
            return files
        files[name] = blob[data_start:data_end]
        cursor = (data_end + 3) & ~3
    raise ValueError("CPIO trailer was not found")


def parse_environment(record: bytes) -> list[dict[str, object]]:
    if len(record) != 0x4000:
        raise ValueError("Unexpected U-Boot environment record size")
    copies = []
    for index in range(2):
        block = record[index * 0x2000:(index + 1) * 0x2000]
        stored_crc = struct.unpack_from("<I", block, 0)[0]
        flag = block[4]
        body = block[5:]
        actual_crc = zlib.crc32(body) & 0xFFFFFFFF
        if stored_crc != actual_crc:
            print(f"environment copy {index}: CRC invalid")
            continue
        variables = {}
        for item in body.split(b"\0"):
            if b"=" in item:
                key, value = item.split(b"=", 1)
                variables[key.decode("ascii")] = value.decode("ascii")
        copies.append({"index": index, "flag": flag, "variables": variables})
        print(f"environment copy {index}: CRC32 OK, flag={flag}, recovery={variables.get('recovery', '?')}")
    return copies


def recover(firmware: Path, show: bool = False) -> bytes:
    raw = firmware.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"Firmware SHA-256 mismatch: {digest}")
    print(f"firmware SHA-256 OK: {digest}")

    records = parse_container(raw)
    dictionary = records["msgcat"]
    inflater = zlib.decompressobj(zdict=dictionary)
    cpio = inflater.decompress(records["rootfs"]) + inflater.flush()
    if len(cpio) != 2560:
        raise ValueError(f"Unexpected decompressed CPIO size: {len(cpio)}")
    files = extract_newc(cpio)
    print(f"rootfs: preset-dictionary DEFLATE -> {len(cpio)}-byte newc CPIO; {len(files)} entries")

    radio = files["etc/config/radio"].decode("ascii")
    token_match = re.search(r"^admin_token=([0-9a-fA-F]+)$", radio, re.MULTILINE)
    if not token_match:
        raise ValueError("admin_token not found in etc/config/radio")
    token = bytes.fromhex(token_match.group(1))

    copies = parse_environment(records["ubootenv"])
    ready = [c for c in copies if c["variables"].get("recovery") == "ready"]
    if len(ready) != 1:
        raise ValueError("Could not identify one CRC-valid recovery=ready environment")
    active = ready[0]
    mac_text = active["variables"].get("ethaddr")
    if not mac_text:
        raise ValueError("ethaddr missing from active U-Boot environment")
    mac = bytes.fromhex(mac_text.replace(":", ""))
    if len(mac) != 6:
        raise ValueError("Unexpected Ethernet MAC length")

    plaintext = bytes(value ^ mac[index % len(mac)] for index, value in enumerate(token))
    if not re.fullmatch(rb"CSCTF\{[A-Za-z0-9_]+\}", plaintext):
        raise ValueError("Recovered token does not match the expected flag syntax")

    print(f"selected environment copy {active['index']} (flag={active['flag']})")
    print(f"XOR key: active environment ethaddr repeated across {len(token)} token bytes")
    print(f"recovered {len(plaintext)} bytes; CSCTF syntax check PASS; SHA-256={hashlib.sha256(plaintext).hexdigest()}")
    if show:
        print(plaintext.decode("ascii"))
    return plaintext


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware", nargs="?", default="firmware.bin")
    parser.add_argument("--show", action="store_true", help="print the recovered plaintext")
    args = parser.parse_args()
    recover(Path(args.firmware), args.show)


if __name__ == "__main__":
    main()
