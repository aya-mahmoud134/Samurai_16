# CSCTF Reverse Engineering — Split Horizon: Vireo Command/Audit Parser Differential

**Division:** `[DIVISION]`  
**Team:** `[TEAM NAME]`  
**Authors:** `[TEAM MEMBERS]`  
**Category:** Reverse Engineering

**Platform:** TL-9 Vireo command and audit pipeline  
**Primary artifacts:** `session.pcap`, `vireo-ctl.dll`, `command-server.go`, `manifest.json`, `audit.log`

## 1. Objective and safety

The incident report says the drone diverged from its approved route while the ground command server recorded a nominal sortie. The task is to determine the waypoint the flight-control client actually used.

The PCAP, .NET assembly and Go source were analyzed as data. The supplied DLL was not executed, and the analysis does not contact a live service.

## 2. Reconstruct the uplink stream

The capture is a classic Ethernet PCAP containing the transfer of the client assembly and a separate TCP command session. The command protocol uses a five-byte frame header:

```text
'V' 'W' | frame_type | payload_length (big-endian, 16-bit)
```

The client sends a type-1 frame containing a 16-byte nonce. The server replies with its own type-1 nonce, followed by encrypted type-2 command frames. Type-3 frames are telemetry and are not passed to the command parser in the client loop.

The solver reassembles the two TCP directions, parses the frame boundaries and extracts the two handshake nonces. It does not print either nonce or the derived session key.

## 3. Recover the session-key derivation from the .NET client

The relevant methods are in `Vireo.Uplink.Protocol`:

- `SharedSecret()` creates a byte array by XORing the two 32-byte static masks.
- `DeriveSessionKey(clientNonce, serverNonce)` concatenates the nonces, computes HMAC-SHA256 using that shared secret, and copies the first 16 digest bytes.
- `Mask(payload, sessionKey)` XORs each payload byte with the repeating 16-byte session key.

The protocol static constructor loads the two mask arrays from PE `FieldRVA` data. The solver maps those RVAs through the PE section table and reconstructs the shared secret without launching the assembly.

The command loop applies `Mask` to each type-2 payload before passing it to `CommandCodec.Parse`.

## 4. Identify the parser mismatch

The client calls `JsonSerializer.Deserialize<CommandEnvelope>(json, Options)`. Its static constructor creates a default `JsonSerializerOptions` object and does not enable case-insensitive property matching. The client therefore uses exact, case-sensitive JSON property-name matching.

The supplied Go server source documents the opposite behavior for `encoding/json`:

- JSON object keys are matched to struct fields case-insensitively.
- When multiple keys match the same field, the later value overwrites the earlier one.

This creates a parser differential when one command contains two spellings of the same field that differ only by case.

## 5. Recover the divergent waypoint

After deriving the session key and decrypting the type-2 frames, eight command messages are recovered. Sequence 1 contains both lower-case and upper-case spellings of the latitude and longitude fields:

```json
{
  "waypoint_lat": 47.3566,
  "waypoint_lon": 18.5182,
  "WAYPOINT_LAT": 47.3548,
  "WAYPOINT_LON": 18.5226
}
```

The client accepts the exact lower-case property names and ignores the case-variant spellings. It therefore sends the drone to:

```text
47.3566, 18.5182
```

The Go server matches both spellings case-insensitively and applies the later values. Its audit record therefore reflects:

```text
47.3548, 18.5226
```

The approved waypoint in `manifest.json` is `47.3555, 18.5234`, with a server tolerance of `0.001` degrees. The logged point is inside that tolerance, while the executed point is outside it. The executed point is approximately 410 metres from the approved waypoint, consistent with the incident note.

The exploited fields are `waypoint_lat+waypoint_lon`; the parser behavior is `case_sensitive_exact_vs_case_insensitive_last_wins`.

## 6. Validate the audit evidence

The solver independently recomputes all eight audit-entry hashes using the formula in `command-server.go`. Every `prev_hash` and `entry_hash` matches, and the final chain root matches the summary.

The Ed25519 signature over the chain root also verifies against the public key in the manifest. This confirms that the audit trail is intact; it does not make the server's parsed coordinates equivalent to the coordinates used by the client.

## 7. Reproduce the analysis

Place the supplied files beside `solve.py`, then run:

```bash
python3 solve.py \
  --pcap session.pcap \
  --dll vireo-ctl.dll \
  --manifest manifest.json \
  --audit audit.log
```

The script uses Python's standard library for PCAP parsing, TCP reassembly, frame parsing, HMAC-SHA256, XOR decoding and audit-chain verification. If the `cryptography` package is installed, it also verifies the Ed25519 signature. It prints the two parsed waypoints and validation results, but never prints the derived session key or handshake nonces.

## 8. Validation

- The PCAP contains a complete client/server handshake and eight type-2 command frames.
- The client protocol methods in the .NET IL establish the key derivation and repeating-XOR mask.
- The decrypted commands reproduce the sequence-1 case-variant duplicate fields.
- Exact-case client parsing yields the executed waypoint; Go-style case-insensitive last-wins parsing yields the audited waypoint.
- The logged waypoint passes the manifest tolerance; the executed waypoint does not.
- All eight audit entries, the chain root and the Ed25519 signature verify.

## AI-assisted methodology
The tool/model, meaningful automation, human checks and genuine workflow screenshots for this challenge are documented in the [consolidated team writeup](../CSCTF-Participant-Writeup.md#ai-assisted-methodology).

## Workflow evidence
See the three genuine terminal workflow screenshots in the [consolidated team writeup](../CSCTF-Participant-Writeup.md#workflow-screenshots).
