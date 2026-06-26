# BARACK-Protect

> **Steganographic Data Vault** — AES-256-GCM · RSA-2048-OAEP · LSB Pixel Matrix  
> *Coded by Barack OS*

A lightweight, fully-offline data vault that hides encrypted secrets invisibly inside
standard digital images using Least Significant Bit (LSB) steganography backed by
hybrid asymmetric cryptography. No network calls. No cloud dependencies. Zero plaintext
ever touches disk.

---

## Table of Contents

1. [Threat Model & Plausible Deniability](#1-threat-model--plausible-deniability)
2. [Architecture Overview](#2-architecture-overview)
3. [Cryptographic Layer](#3-cryptographic-layer)
4. [Steganographic Layer — LSB Bit-Masking Architecture](#4-steganographic-layer--lsb-bit-masking-architecture)
5. [Wire Formats](#5-wire-formats)
6. [Installation](#6-installation)
7. [Usage](#7-usage)
8. [Security Analysis](#8-security-analysis)
9. [File Structure](#9-file-structure)

---

## 1. Threat Model & Plausible Deniability

### Threat Actors Considered

| Threat | Mitigation |
|---|---|
| Passive observer with physical access to image file | Image is visually identical to any normal PNG; no metadata signals the presence of hidden data |
| Adversary with steganalysis tools (χ² test, RS analysis) | Payload is encrypted random-looking ciphertext; statistical LSB distribution approaches uniform noise |
| Attacker who knows BARACK-Protect was used | AES-256-GCM ciphertext is computationally indistinguishable from randomness without the RSA private key |
| Key theft (public key compromise) | Public key only encrypts — recovery of plaintext still requires the private key |
| Brute-force of AES session key | 256-bit keyspace — infeasible for all known classical computing resources |
| Chosen-plaintext / chosen-ciphertext attacks on GCM | AESGCM from the `cryptography` library is immune by design; any ciphertext modification causes tag rejection |

### Plausible Deniability Chain

```
Original PNG/JPG → looks like: holiday photo, diagram, avatar, any image
     ↓  LSB injection
Stego PNG        → visually identical; PSNR degradation < 0.001 dB for small payloads
     ↓  adversarial extraction attempt (without key)
Raw bytes        → 100% high-entropy binary blob indistinguishable from camera noise
     ↓  RSA-OAEP + AES-GCM without private key
Plaintext        → computationally unrecoverable (2^256 AES keyspace)
```

An adversary who recovers the image cannot prove that:
- The image contains hidden data (statistical deniability when payload-to-capacity ratio is low)
- Any recovered blob is meaningful (cryptographic deniability without the private key)

---

## 2. Architecture Overview

```
┌────────────────────────────────────────────────────────────────────┐
│                         main.py  (CLI)                             │
│  ANSI terminal · interactive prompts · BARACK OS ASCII banner      │
└───────────┬──────────────────────────────────────┬─────────────────┘
            │                                      │
            ▼                                      ▼
┌───────────────────────┐              ┌───────────────────────────┐
│    crypto_core.py     │              │     stego_engine.py       │
│                       │              │                           │
│  RSA-2048 key gen     │              │  Pillow image I/O         │
│  RSA-OAEP key wrap    │◄────blob────►│  LSB injection matrix     │
│  AES-256-GCM encrypt  │              │  LSB extraction matrix    │
│  SHA-256 fingerprint  │              │  capacity guard           │
└───────────────────────┘              └───────────────────────────┘
            │
            ▼
  ~/.barack_protect/
    ├── private_key.pem   ← NEVER share
    └── public_key.pem    ← distribute freely
```

**Data flow — Encode path:**

```
plaintext_secret
      │
      ▼
encrypt_payload(plaintext, pub_key)
      │  AES-256-GCM(session_key, nonce, plaintext) + RSA-OAEP(pub_key, session_key)
      ▼
encrypted_blob  ──►  inject_secret_into_image(cover.png, blob)
                            │  LSB overwrite in RGB channel stream
                            ▼
                       stego_output.png
```

**Data flow — Decode path:**

```
stego_output.png
      │
      ▼
extract_secret_from_image(stego.png)
      │  LSB harvest → length header → payload bits
      ▼
encrypted_blob  ──►  decrypt_payload(blob, priv_key)
                            │  RSA-OAEP → session_key  →  AES-GCM.decrypt
                            ▼
                       plaintext_secret
```

---

## 3. Cryptographic Layer

### Hybrid Encryption Rationale

RSA cannot directly encrypt large payloads efficiently. The hybrid approach
(AES session key wrapped with RSA) is the industry-standard solution and is
identical to what TLS 1.3, PGP, and Signal use.

### AES-256-GCM

- **Key size:** 256 bits (32 bytes), freshly generated via `os.urandom` for every encode operation.
- **Nonce:** 96 bits (12 bytes) random — the optimal nonce length for GCM.
- **Authentication tag:** 128 bits (16 bytes) appended to ciphertext by the `AESGCM` primitive.
- **Property:** Provides simultaneous confidentiality, integrity, and authenticity (AEAD).
  Any single-bit modification of the ciphertext or tag causes decryption to raise an exception.

### RSA-2048-OAEP

- **Key size:** 2048 bits.
- **Padding:** OAEP with SHA-256 mask generation function (MGF1).
- **Purpose:** Encrypts the 32-byte AES session key only — never the plaintext directly.
- **Maximum payload for OAEP/SHA-256:** `2048/8 − 2×32 − 2 = 190 bytes`, which comfortably
  covers the 32-byte AES key.

### Key Storage

Keys are persisted as PEM-encoded files:

| File | Content | Sensitivity |
|---|---|---|
| `private_key.pem` | PKCS#1 TraditionalOpenSSL RSA private key | **SECRET — never share** |
| `public_key.pem` | SubjectPublicKeyInfo DER-encoded public key | Safe to distribute |

The SHA-256 fingerprint of the DER-encoded public key blob is displayed as a hex string
for out-of-band verification (similar to SSH host key fingerprints).

---

## 4. Steganographic Layer — LSB Bit-Masking Architecture

### Principle

Every pixel in an RGB image is represented by three bytes: Red, Green, Blue.
Each byte has 8 bits. The **Least Significant Bit** (bit 0) of each channel
contributes only `1/256` of the total channel value — a single greyscale step
that is entirely imperceptible to human vision.

```
Original pixel byte:   1 0 1 1 0 1 1 0   (0xB6 = 182)
                       ↑                 ← MSB (most significant, high visual impact)
                                     ↑   ← LSB (targeted by BARACK-Protect)

After LSB replacement: 1 0 1 1 0 1 1 [X]
  X=0 → 0xB6 = 182
  X=1 → 0xB7 = 183   ← difference: 1 grey level out of 256 — human vision threshold ~5
```

### Bit-Masking Operation

**Injection (clear LSB then set):**
```python
channel_byte = (original_byte & 0xFE) | secret_bit
#                              ^^^^^^     ^^^^^^^^^^
#                          mask 0b11111110  OR the new bit
```

**Extraction:**
```python
secret_bit = channel_byte & 0x01
#                           ^^^^^^
#                       mask 0b00000001
```

### Channel Stream Layout

Pixels are processed in row-major order (left→right, top→bottom).
Within each pixel, channels are ordered R→G→B.
The flat channel index maps to `(pixel_index, channel)` as:

```
channel_offset = pixel_index × 3 + channel_index

offset 0  → pixel[0].R
offset 1  → pixel[0].G
offset 2  → pixel[0].B
offset 3  → pixel[1].R
offset 4  → pixel[1].G
...
```

### Capacity Formula

```
max_payload_bytes = (width × height × 3) ÷ 8  −  4
                    ─────────────────────────     ─
                    total LSB bits / 8 = bytes   header overhead
```

Example capacities:

| Image Size | Dimensions | Max Payload |
|---|---|---|
| Small thumbnail | 256 × 256 | ~24 KB |
| Standard photo | 1920 × 1080 | ~741 KB |
| High-res image | 3840 × 2160 | ~2.96 MB |
| 4K poster | 7680 × 4320 | ~11.8 MB |

---

## 5. Wire Formats

### 5.1 Hybrid Encryption Blob (`crypto_core.encrypt_payload` output)

```
Offset    Size     Field
──────────────────────────────────────────────────────
0         4 B      rsa_blob_len  — big-endian uint32
4         N B      rsa_blob      — RSA-OAEP(pub_key, aes_session_key)
4+N       12 B     nonce         — random GCM nonce (96-bit)
4+N+12    L+16 B   ciphertext    — AES-256-GCM(session_key, nonce, plaintext)
                                   last 16 bytes = GCM authentication tag
```

For RSA-2048: `N = 256`. Total overhead per encode: `4 + 256 + 12 + 16 = 288 bytes`.

### 5.2 Pixel Channel Stream (`stego_engine` layout)

```
Channel offset    Content
─────────────────────────────────────────────────────────────────────
[0   .. 31]       32 bits = 4-byte big-endian uint32 payload length L
[32  .. 32+L×8-1] L×8 bits = encrypted blob from §5.1, MSB-first per byte
[32+L×8 ..]       Untouched original LSBs (natural image noise)
```

---

## 6. Installation

**Requirements:** Python 3.9+

```bash
# Clone or copy the project folder
cd "barack protect"

# Install dependencies
pip install -r requirements.txt
```

`requirements.txt`:
```
cryptography>=41.0.0
Pillow>=10.0.0
```

---

## 7. Usage

```bash
python main.py
```

The system boots with a full-screen ANSI green ASCII art banner and presents
the interactive menu. All operations are driven through numbered choices and
plain path prompts — no flags or subcommands required.

### Workflow: First Use

```
3 → Generate RSA-2048 keypair  (saved to ~/.barack_protect/)
1 → Encode: enter secret, pick a cover image, get stego PNG
2 → Decode: pick the stego PNG, recovers and decrypts the secret
```

### Workflow: Share a Secret

```
Sender:   share public_key.pem  out-of-band (email, USB, etc.)
Sender:   python main.py → 1 → encode with RECIPIENT's public key
          → sends stego PNG (looks like any image)
Receiver: python main.py → 2 → decode with their own private key
```

---

## 8. Security Analysis

### Strengths

- **Forward secrecy per message:** Each encode generates a fresh AES session key via
  `os.urandom(32)`. Compromise of one session key reveals only that message.
- **Authenticated encryption:** AES-256-GCM's 128-bit tag means any tampering with the
  stego image or extracted blob raises a hard error before any plaintext is returned.
- **No key derivation from passwords:** Session keys are purely random, eliminating
  dictionary and brute-force attacks on key derivation.
- **Lossless output format:** Output is always PNG, preserving LSBs exactly. The system
  explicitly refuses to embed in already-compressed image formats (JPEG is read-only cover).
- **Zero network surface:** All operations are local. The attack surface is limited to
  the host filesystem.

### Known Limitations

- **Cover image reuse:** Embedding different secrets in the same cover image with the
  same position offset is detectable by differential analysis. Always use fresh covers
  or randomise the start offset (future enhancement).
- **Steganalysis on low-capacity images:** If the payload-to-capacity ratio exceeds
  ~30%, statistical tests (RS analysis, sample pairs) may detect anomalous LSB
  distributions. Use cover images at least 10× larger than the payload.
- **Private key storage:** The private key is stored unencrypted by default. Users in
  high-threat environments should encrypt `private_key.pem` with a passphrase (future
  enhancement: `BestAvailableEncryption`).
- **Side-channel:** An adversary with read access to the filesystem and knowledge that
  BARACK-Protect is installed may infer usage from the presence of `~/.barack_protect/`.

---

## 9. File Structure

```
barack protect/
├── crypto_core.py      — RSA-2048 keypair management + AES-256-GCM hybrid encryption
├── stego_engine.py     — LSB injection / extraction matrix using Pillow
├── main.py             — Interactive ANSI CLI orchestrator, ASCII banner, menu loop
├── requirements.txt    — Python package dependencies
└── README.md           — This document
```

---

*BARACK-Protect — Coded by Barack OS*
