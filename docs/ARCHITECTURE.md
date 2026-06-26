# BARACK-Protect — Architecture & Design Rationale

> Steganographic Data Vault  
> AES-256-GCM · RSA-2048-OAEP · LSB Pixel Matrix  
> Coded by Barack OS

---

## Why This Project Matters

In an era where digital surveillance is pervasive and data breaches expose millions of people every year, the ability to communicate and store secrets securely is no longer a luxury reserved for governments and corporations. It is a fundamental right for every individual.

Most encryption tools make it obvious that secret communication is happening. Sending an encrypted file immediately signals to an adversary that something sensitive is being transmitted. This is where BARACK-Protect takes a different approach.

BARACK-Protect does not just encrypt data. It makes the existence of that data invisible. By hiding encrypted payloads inside ordinary image files, it grants the user a powerful property called plausible deniability. An image of a landscape, a portrait, or a screenshot looks entirely normal to any observer, automated scanner, or forensic tool, while silently carrying a secret that only the intended recipient can recover.

This is critical in contexts where:

* Journalists need to protect sources in authoritarian environments
* Activists must transmit sensitive plans without triggering surveillance
* Businesses need to share proprietary data without leaving an obvious trail
* Individuals want to archive personal secrets that must survive even physical device seizure

BARACK-Protect runs entirely offline. No server receives your data. No cloud stores your keys. The entire system lives on your machine, under your control.

---

## High-Level Architecture

The system is composed of three independent modules that stack on top of each other.

```
┌──────────────────────────────────────────────────────┐
│                    main.py                           │
│   Interactive CLI · ASCII banner · Menu routing      │
└────────────────────┬─────────────────────────────────┘
                     │
         ┌───────────┴───────────┐
         │                       │
         ▼                       ▼
┌────────────────┐     ┌─────────────────────┐
│ crypto_core.py │     │  stego_engine.py    │
│                │     │                     │
│ RSA-2048 keys  │     │ Pillow image I/O    │
│ AES-256-GCM    │────►│ LSB bit injection   │
│ Fingerprints   │     │ LSB bit extraction  │
└────────────────┘     └─────────────────────┘
         │
         ▼
  ~/.barack_protect/
    private_key.pem
    public_key.pem
```

The CLI layer orchestrates user input and delegates all cryptographic and steganographic work to the two core modules. Neither core module knows anything about the terminal or the user interface. This separation means each module can be audited, tested, and replaced independently.

---

## Module 1 — crypto_core.py

### Purpose

This module is responsible for all cryptographic operations. It ensures that even if an adversary extracts the hidden data from an image, they cannot read it without the private key.

### RSA-2048 Key Management

The system uses asymmetric cryptography based on the RSA algorithm with a 2048-bit key. Two keys are generated together and are mathematically linked:

* The public key encrypts data. It can be shared freely with anyone.
* The private key decrypts data. It must never leave the owner's control.

Key generation uses the `cryptography` library from the Python Packaging Authority, which internally uses OpenSSL. The private key is written to disk using an atomic write pattern: first to a temporary file with restricted permissions (mode 0o600, readable only by the owner), then renamed into its final location in a single system call. This guarantees that no partial or unprotected key file ever exists on disk, even if the process is interrupted.

### Why Hybrid Encryption

RSA alone cannot encrypt large messages efficiently. The maximum plaintext size for RSA-2048 with OAEP padding is approximately 190 bytes. A real secret, such as a document or a long message, would exceed this limit.

The solution is hybrid encryption, which is the same approach used by TLS, PGP, and Signal:

```
1. Generate a random 256-bit AES session key  (os.urandom — cryptographically secure)
2. Encrypt the secret with AES-256-GCM        (fast, no size limit)
3. Encrypt the AES key with RSA-2048-OAEP     (small input, fits perfectly)
4. Bundle: [RSA blob length] + [RSA blob] + [nonce] + [ciphertext + tag]
```

The AES session key is freshly generated for every single encode operation. This means that compromise of one session key reveals only one message, not all messages ever sent. This property is called per-message forward secrecy.

### AES-256-GCM

AES-256-GCM is an Authenticated Encryption with Associated Data (AEAD) cipher. It provides three guarantees simultaneously:

* Confidentiality: the content cannot be read without the key
* Integrity: any modification of the ciphertext is detected
* Authenticity: the decryptor knows the data came from someone who held the key

The 128-bit authentication tag appended to every ciphertext means that even a single flipped bit in the stored data will cause decryption to fail loudly, rather than silently returning corrupted plaintext.

### Wire Format of the Encrypted Blob

```
Offset     Size      Field
────────────────────────────────────────────────────
0          4 bytes   Length of RSA block (big-endian uint32)
4          256 bytes RSA-OAEP encrypted AES session key
260        12 bytes  GCM nonce (randomly generated)
272        variable  AES-256-GCM ciphertext with 16-byte tag appended
```

Total fixed overhead per message: 288 bytes. Everything beyond that is proportional to the plaintext size.

---

## Module 2 — stego_engine.py

### Purpose

This module takes the encrypted blob produced by crypto_core and hides it inside a standard image file by manipulating individual pixel bits. To an observer, the output image is indistinguishable from the original.

### The Least Significant Bit Technique

Every pixel in an RGB image is represented by three bytes: one for Red, one for Green, one for Blue. Each byte is an integer from 0 to 255.

The rightmost bit of each byte is called the Least Significant Bit (LSB). Changing it shifts the color value by exactly 1 step out of 256. The human visual system cannot detect differences smaller than roughly 5 steps, so a single-step change is completely invisible.

```
Original Red channel byte:    1 0 1 1 0 1 1 0   (value 182)
                                               ↑
                                           This bit carries one bit of secret data

Modified byte (bit set to 1): 1 0 1 1 0 1 1 1   (value 183)
Difference: 1 out of 256 color levels — invisible to the human eye
```

### Bit Injection

The injection operation clears the LSB of the original byte and replaces it with one bit of the payload:

```python
channel_byte = (original_byte & 0xFE) | secret_bit
```

The mask `0xFE` in binary is `11111110`. The AND operation zeroes only the last bit, preserving the other seven. The OR then writes the secret bit into that position.

### Bit Extraction

Extraction is the reverse:

```python
secret_bit = channel_byte & 0x01
```

The mask `0x01` in binary is `00000001`. The AND isolates only the last bit.

### Channel Stream Layout

Pixels are processed in row-major order, left to right, top to bottom. Within each pixel, the three channels are processed in order: Red, then Green, then Blue.

```
Channel index 0   →  pixel[0].Red
Channel index 1   →  pixel[0].Green
Channel index 2   →  pixel[0].Blue
Channel index 3   →  pixel[1].Red
Channel index 4   →  pixel[1].Green
...and so on
```

The first 32 channel LSBs always carry the payload length as a 4-byte big-endian unsigned integer. All subsequent LSBs carry the encrypted payload bits. Channels beyond the payload are left untouched, preserving their original LSB noise.

### Image Capacity

```
Maximum storable bytes = (width × height × 3) ÷ 8  minus  4 bytes overhead
```

For reference:

| Image Resolution  | Maximum Payload     |
|---|---|
| 256 × 256         | approximately 24 KB |
| 1920 × 1080       | approximately 741 KB |
| 3840 × 2160       | approximately 2.96 MB |

### Why Output Is Always PNG

JPEG compression is lossy. It modifies pixel values to achieve smaller file sizes, which would destroy the LSBs carrying the hidden payload. The stego engine always writes the output as PNG regardless of the extension supplied by the user, because PNG is lossless and preserves every pixel exactly.

---

## Module 3 — main.py

### Purpose

This module is the user-facing shell of the application. It clears the terminal, renders the ASCII banner, presents the menu, collects input, and delegates to the two core modules.

### Encode Flow

```
User enters secret text or selects a file
          ↓
encrypt_payload(secret, public_key_path)
          ↓
inject_secret_into_image(cover_image, encrypted_blob, output_path)
          ↓
Output PNG appears in the chosen location
```

### Decode Flow

```
User selects a stego image
          ↓
extract_secret_from_image(stego_image_path)
          ↓
decrypt_payload(encrypted_blob, private_key_path)
          ↓
Plaintext displayed or saved to file
```

### Signal Handling

Pressing Ctrl+C at any point in the application produces a clean exit rather than a Python traceback. Inside a flow, Ctrl+C cancels the current operation and returns to the main menu silently. At the main menu, Ctrl+C exits the program.

---

## Security Model Summary

| Property              | Mechanism                                              |
|---|---|
| Confidentiality       | AES-256-GCM encryption before embedding               |
| Integrity             | GCM authentication tag detects any tampering          |
| Invisibility          | LSB substitution — 1 color step change per channel    |
| Plausible deniability | Output is a valid PNG file with no metadata markers   |
| Key security          | RSA private key written with atomic rename and 0o600  |
| Forward secrecy       | Fresh random AES key generated per encode operation   |

---

## File Structure

```
barack protect/
    crypto_core.py      RSA-2048 key management and AES-256-GCM encryption
    stego_engine.py     LSB injection and extraction using Pillow
    main.py             Interactive CLI orchestrator with ASCII banner
    requirements.txt    Python package dependencies
    README.md           Project overview and usage guide
    docs/
        ARCHITECTURE.md     This document
```

---

*BARACK-Protect — Coded by Barack OS*
