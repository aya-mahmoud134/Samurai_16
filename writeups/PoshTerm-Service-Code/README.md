# CSCTF Reverse Engineering — PoshTerm Hidden Service Code

**Division:** `[DIVISION]`  
**Team:** `[TEAM NAME]`  
**Authors:** `[TEAM MEMBERS]`  
**Category:** Reverse Engineering  
**Archive:** `chall.7z`  
**Archive SHA-256:** `a771296d0470a82a8d6080ba8967cb0b0cab589a31b0b6664e0722892dc27031`  
**Executable:** `PoshTerm.exe` (227,812,228 bytes)  
**Executable SHA-256:** `a20d559ea90c7f64241314863c4ee194f8dc1467d42eaf6211c43de7f530f135`

## 1. Objective and handling

The archive contains a Windows x64 terminal application and its user guide. The task is to recover the output of a hidden service command. The executable is a self-contained PE with a large embedded JavaScript bundle.

The executable was not launched. All inspection was performed against the archive contents and raw PE bytes.

## 2. Locate the hidden command

A static search for `service_code` locates the command registration inside the embedded JavaScript bundle (around file offset `0x62d3700`). The registration marks the command as hidden, so it is not part of the normal command listing.

The handler checks two MD5 conditions before invoking its asynchronous helper:

- The MD5 of the `POSHTERM_PROFILE` environment variable must match an embedded host constant.
- The MD5 of the final command argument must match the embedded code constant.

The handler compares the MD5 of `POSHTERM_PROFILE` with the embedded host digest `52d960bf972119685d50c3d33f737665`. The separate code-argument digest is:

```text
e3db766fd63bf1afdd34abcac1f5c112
```

This matches the MD5 of the exact UTF-8 string `Cessna 421 Golden Eagle`. The command parser also requires an equals sign before the argument. These checks explain why simply trying the obvious command or reading the visible decoy commands is not enough.

The application also registers visible decoy commands and decoy flag strings. Those are not used in the real service-code path.

## 3. Trace the service-code helper

The hidden handler calls an asynchronous helper that performs the following steps:

1. Search Wikipedia for the supplied aircraft name.
2. Fetch the selected article and locate the `first_flight` section.
3. Extract the date from the article text using a month/day/year pattern.
4. Normalize the date as `YYYY-MM-DD`.
5. Request a Julian date from the JPL `jd_cal` service using seven decimal places.
6. Convert the returned Julian-date string to UTF-8 bytes and use those bytes as the RC4 key.
7. Decrypt a 48-byte hexadecimal payload embedded directly in the JavaScript.

The embedded helper is important because it reveals the key derivation exactly. There is no need to guess passwords or brute-force the RC4 key.

## 4. Derive the key offline

The aircraft reference is `Cessna 421 Golden Eagle`. Its first-flight date is 14 October 1965. This date is independently corroborated by the aircraft history and a NASA technical report ([NASA NTRS](https://ntrs.nasa.gov/api/citations/19740023386/downloads/19740023386_Update.pdf); [Wikipedia article](https://en.wikipedia.org/wiki/Cessna_421_Golden_Eagle)). The Julian date at 00:00 UT for that date is:

```text
2439047.5000000
```

The application passes the string representation to RC4, so the key is the ASCII byte sequence for `2439047.5000000`, not an integer or floating-point binary representation. The corresponding JPL endpoint used by the application is `https://ssd-api.jpl.nasa.gov/jd_cal.api?format=jd.7&cd=1965-10-14`.

The ciphertext embedded in the JavaScript is:

```text
37f1f43867e61d207c0b78ca4385ee14
f67d98e0c0cdbe6e5027ff506e302cb6
6b8c8c5ad07d726c0e24e9f13bbcdfa9
```

The `j()` helper is a conventional RC4 implementation: it initializes the 256-byte permutation, performs the key-scheduling algorithm, then generates the keystream with the PRGA and XORs it with the ciphertext.

## 5. Why the environment guard does not block static recovery

The environment check controls whether the hidden command can be invoked through the application's shell. It is not part of the cryptographic transformation itself. The helper contains the complete ciphertext and the RC4 routine, and the date-to-key process is explicit.

Therefore the service output can be reproduced offline without setting `POSHTERM_PROFILE`, satisfying the command dispatcher, or executing the PE. The solver checks the embedded command markers and the known MD5 for the aircraft argument, computes the Julian date locally, and performs the same RC4 operation.

## 6. Reproducible solver

With the extracted `PoshTerm.exe` in the current directory:

```bash
python3 solve.py PoshTerm.exe
```

The solver checks the executable SHA-256, confirms that the hidden command and helper markers are present, verifies the aircraft argument's MD5, computes the Julian date, and runs RC4. It reports the recovered plaintext length, syntax check and SHA-256 without echoing the plaintext by default.

To display the recovered value locally:

```bash
python3 solve.py PoshTerm.exe --show
```

## 7. Validation

- The 7z archive and extracted PE hashes were checked against the supplied artifacts / prior extraction record.
- The hidden `service_code` registration, environment-variable guard, MD5 helper and `first_flight` lookup were found in the PE's embedded JavaScript.
- The aircraft string's MD5 matches the constant in the handler.
- The date calculation independently produces the seven-decimal Julian-date string used by the application.
- RC4 decrypts the exact embedded 48-byte payload into a 48-byte string matching the challenge's flag syntax.
- The Windows executable was never run.

## 8. AI methodology

- **Tool/model:** ChatGPT GPT-6 assisted with static code interpretation and the writeup structure. The executable was inspected as raw data; no AI-generated output was accepted without byte-level checks.
- **Meaningful automation:** Python was used to search PE bytes for embedded JavaScript markers, verify hashes and the MD5 gate, calculate the Julian date, and reproduce RC4.
- **Human checks:** The hidden handler and RC4 implementation were read directly from the embedded bundle; the MD5 of the aircraft string was independently calculated; the Julian date was independently derived; and the ciphertext length and decrypted syntax were checked.
- **Safety:** The PE was not executed, and the service helper's network calls were not invoked. The output was reconstructed locally from the embedded algorithm and data.

### Workflow evidence

The genuine terminal workflow screenshots are collected in the [consolidated team writeup](../CSCTF-Participant-Writeup.md#workflow-screenshots).
