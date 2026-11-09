#!/usr/bin/env python3
"""Offline Split Horizon analysis. Does not execute the DLL or contact a live service."""

import argparse
import base64
import hashlib
import hmac
import json
import socket
import struct
from collections import defaultdict
from pathlib import Path


def parse_pcap(path):
    raw = Path(path).read_bytes()
    magic = raw[:4]
    if magic == bytes.fromhex("d4c3b2a1"):
        endian = "<"
    elif magic == bytes.fromhex("a1b2c3d4"):
        endian = ">"
    elif magic == bytes.fromhex("4d3cb2a1"):
        endian = "<"
    elif magic == bytes.fromhex("a1b23c4d"):
        endian = ">"
    else:
        raise ValueError("Unsupported PCAP magic")
    _, _, _, _, _, linktype = struct.unpack_from(endian + "HHIIII", raw, 4)
    if linktype != 1:
        raise ValueError("Expected Ethernet PCAP")
    flows = defaultdict(list)
    offset = 24
    while offset + 16 <= len(raw):
        _, _, captured, _ = struct.unpack_from(endian + "IIII", raw, offset)
        offset += 16
        frame = raw[offset:offset + captured]
        offset += captured
        if len(frame) < 14 or struct.unpack_from(">H", frame, 12)[0] != 0x0800:
            continue
        ip = frame[14:]
        if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
            continue
        ip_len = (ip[0] & 15) * 4
        total_len = struct.unpack_from(">H", ip, 2)[0]
        ip = ip[:total_len]
        tcp = ip[ip_len:]
        if len(tcp) < 20:
            continue
        sport, dport, seq = struct.unpack_from(">HHI", tcp, 0)
        tcp_len = (tcp[12] >> 4) * 4
        payload = tcp[tcp_len:]
        if payload:
            src = socket.inet_ntoa(ip[12:16])
            dst = socket.inet_ntoa(ip[16:20])
            flows[(src, sport, dst, dport)].append((seq, payload))
    return flows


def reassemble(segments):
    output = bytearray()
    expected = None
    for seq, payload in sorted(segments, key=lambda item: item[0]):
        if expected is None:
            expected = seq
        if seq > expected:
            raise ValueError("TCP stream contains a sequence gap")
        overlap = expected - seq
        if overlap < len(payload):
            tail = payload[overlap:]
            output.extend(tail)
            expected += len(tail)
    return bytes(output)


def parse_frames(stream):
    frames = []
    offset = 0
    while offset < len(stream):
        if offset + 5 > len(stream) or stream[offset:offset + 2] != b"VW":
            raise ValueError(f"Invalid frame at offset {offset}")
        kind = stream[offset + 2]
        size = int.from_bytes(stream[offset + 3:offset + 5], "big")
        offset += 5
        payload = stream[offset:offset + size]
        if len(payload) != size:
            raise ValueError("Truncated frame")
        frames.append((kind, payload))
        offset += size
    return frames


def rva_to_offset(pe, rva):
    peoff = struct.unpack_from("<I", pe, 0x3C)[0]
    if pe[peoff:peoff + 4] != b"PE\0\0":
        raise ValueError("Invalid PE signature")
    count = struct.unpack_from("<H", pe, peoff + 6)[0]
    opt_size = struct.unpack_from("<H", pe, peoff + 20)[0]
    section_table = peoff + 24 + opt_size
    for i in range(count):
        entry = section_table + i * 40
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", pe, entry + 8)
        if va <= rva < va + max(vsize, rawsize):
            return rawptr + rva - va
    raise ValueError(f"RVA {rva:#x} not found")


def shared_secret_from_dll(path):
    pe = Path(path).read_bytes()
    a = rva_to_offset(pe, 0x3BC8)
    b = rva_to_offset(pe, 0x3BA8)
    mask_a, mask_b = pe[a:a + 32], pe[b:b + 32]
    if len(mask_a) != 32 or len(mask_b) != 32:
        raise ValueError("Static mask arrays are incomplete")
    return bytes(x ^ y for x, y in zip(mask_a, mask_b))


def last_case_insensitive(obj, wanted):
    found = None
    for name, value in obj.items():
        if name.casefold() == wanted.casefold():
            found = value
    if found is None:
        raise KeyError(wanted)
    return float(found)


def verify_audit(path, manifest):
    rows = [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]
    if not rows:
        raise ValueError("Empty audit log")
    entries, summary = rows[:-1], rows[-1]
    previous = bytes(32)
    for item in entries:
        prev_hex = previous.hex()
        if item["prev_hash"] != prev_hex:
            raise ValueError(f"Previous-hash mismatch at sequence {item['seq']}")
        body = f"{prev_hex}|{item['seq']}|{item['status']}|{item['waypoint_commit']}".encode()
        previous = hashlib.sha256(previous + body).digest()
        if item["entry_hash"] != previous.hex():
            raise ValueError(f"Entry-hash mismatch at sequence {item['seq']}")
    if summary["chain_root"] != previous.hex():
        raise ValueError("Audit root mismatch")
    if summary["pubkey"] != manifest["audit_pubkey_b64"]:
        raise ValueError("Audit public key does not match manifest")
    signature_valid = None
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(base64.b64decode(summary["pubkey"])).verify(
            base64.b64decode(summary["sig"]), bytes.fromhex(summary["chain_root"])
        )
        signature_valid = True
    except ImportError:
        pass
    return entries, signature_valid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", default="session.pcap")
    parser.add_argument("--dll", default="vireo-ctl.dll")
    parser.add_argument("--manifest", default="manifest.json")
    parser.add_argument("--audit", default="audit.log")
    args = parser.parse_args()
    manifest = json.loads(Path(args.manifest).read_text())
    flows = parse_pcap(args.pcap)
    c2s, s2c = [], []
    for (_, sport, _, dport), segments in flows.items():
        if dport == 8642:
            c2s.extend(segments)
        elif sport == 8642:
            s2c.extend(segments)
    client_frames = parse_frames(reassemble(c2s))
    server_frames = parse_frames(reassemble(s2c))
    client_nonce = next(data for kind, data in client_frames if kind == 1 and len(data) == 16)
    server_nonce = next(data for kind, data in server_frames if kind == 1 and len(data) == 16)
    secret = shared_secret_from_dll(args.dll)
    session_key = hmac.new(secret, client_nonce + server_nonce, hashlib.sha256).digest()[:16]
    commands = []
    for kind, ciphertext in server_frames:
        if kind != 2:
            continue
        plaintext = bytes(value ^ session_key[i % 16] for i, value in enumerate(ciphertext))
        command = json.loads(plaintext.decode("utf-8"))
        params = command["params"]
        executed = (float(params["waypoint_lat"]), float(params["waypoint_lon"]))
        logged = (
            last_case_insensitive(params, "waypoint_lat"),
            last_case_insensitive(params, "waypoint_lon"),
        )
        commands.append((int(command["seq"]), executed, logged))
    audit, signature_valid = verify_audit(args.audit, manifest)
    audit_status = {int(row["seq"]): row["status"] for row in audit}
    anomalies = [row for row in commands if row[1] != row[2]]
    if len(anomalies) != 1:
        raise ValueError(f"Expected one parser differential, found {len(anomalies)}")
    seq, executed, logged = anomalies[0]
    approved = (float(manifest["approved_waypoint_lat"]), float(manifest["approved_waypoint_lon"]))
    tolerance = float(manifest["server_validation_tolerance_deg"])
    logged_ok = abs(logged[0] - approved[0]) <= tolerance and abs(logged[1] - approved[1]) <= tolerance
    executed_ok = abs(executed[0] - approved[0]) <= tolerance and abs(executed[1] - approved[1]) <= tolerance
    if audit_status.get(seq) != "NOMINAL" or not logged_ok or executed_ok:
        raise ValueError("Recovered parser differential does not match the incident evidence")
    print(f"Decrypted command frames: {len(commands)}")
    print(f"Parser-differential sequence: {seq}")
    print(f"Executed waypoint (exact-case client): {executed[0]:.4f}, {executed[1]:.4f}")
    print(f"Logged waypoint (Go last-wins parser): {logged[0]:.4f}, {logged[1]:.4f}")
    print(f"Approved waypoint: {approved[0]:.4f}, {approved[1]:.4f}")
    print(f"Logged waypoint within tolerance: {logged_ok}")
    print(f"Executed waypoint within tolerance: {executed_ok}")
    print(f"Audit chain entries verified: {len(audit)}")
    print(f"Ed25519 signature valid: {signature_valid if signature_valid is not None else 'not checked'}")
    print("Mechanism: case_sensitive_exact_vs_case_insensitive_last_wins")
    print("Exploited fields: waypoint_lat+waypoint_lon")


if __name__ == "__main__":
    main()
