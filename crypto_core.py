"""
BARACK-Protect — Cryptographic Core
Hybrid RSA-2048-OAEP / AES-256-GCM encryption engine for offline data vaulting.
"""

from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_BACKEND = default_backend()
_RSA_KEY_BITS: int = 2048
_RSA_PUBLIC_EXPONENT: int = 65537
_RSA_BLOB_BYTES: int = _RSA_KEY_BITS // 8  # 256 — exact RSA-OAEP ciphertext length
_AES_KEY_BYTES: int = 32       # AES-256
_GCM_NONCE_BYTES: int = 12     # 96-bit nonce, optimal for GCM
_GCM_TAG_BYTES: int = 16       # 128-bit authentication tag

_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def generate_rsa_keypair(private_key_path: str, public_key_path: str) -> None:
    """Generate a fresh RSA-2048 keypair and persist both PEM files to disk.

    Both files are written to temporary siblings first, then atomically renamed
    so a crash or disk-full error between the two writes never leaves an orphaned
    private key on disk without its matching public key.  The private key temp
    file is restricted to 0o600 before the rename so it is never world-readable,
    even briefly.
    """
    private_key = rsa.generate_private_key(
        public_exponent=_RSA_PUBLIC_EXPONENT,
        key_size=_RSA_KEY_BITS,
        backend=_BACKEND,
    )
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_dest = Path(private_key_path)
    pub_dest  = Path(public_key_path)
    priv_dest.parent.mkdir(parents=True, exist_ok=True)
    pub_dest.parent.mkdir(parents=True, exist_ok=True)

    priv_tmp: Path | None = None
    pub_tmp:  Path | None = None
    try:
        fd, tmp = tempfile.mkstemp(dir=priv_dest.parent, suffix=".tmp")
        priv_tmp = Path(tmp)
        try:
            os.write(fd, priv_pem)
        finally:
            os.close(fd)
        os.chmod(priv_tmp, 0o600)

        fd, tmp = tempfile.mkstemp(dir=pub_dest.parent, suffix=".tmp")
        pub_tmp = Path(tmp)
        try:
            os.write(fd, pub_pem)
        finally:
            os.close(fd)

        os.replace(priv_tmp, priv_dest)
        priv_tmp = None
        os.replace(pub_tmp, pub_dest)
        pub_tmp = None
    finally:
        if priv_tmp is not None:
            priv_tmp.unlink(missing_ok=True)
        if pub_tmp is not None:
            pub_tmp.unlink(missing_ok=True)


def load_private_key(path: str):
    """Deserialize a PEM-encoded RSA private key from disk."""
    return serialization.load_pem_private_key(
        Path(path).read_bytes(), password=None, backend=_BACKEND
    )


def load_public_key(path: str):
    """Deserialize a PEM-encoded RSA public key from disk."""
    return serialization.load_pem_public_key(
        Path(path).read_bytes(), backend=_BACKEND
    )


def encrypt_payload(plaintext: bytes, public_key_path: str) -> bytes:
    """
    Hybrid-encrypt plaintext using AES-256-GCM with RSA-2048-OAEP key wrapping.

    Wire format of the returned blob:
        [ 4 B  ]  rsa_blob_len  — big-endian uint32 byte count of the RSA ciphertext
        [ N B  ]  rsa_blob      — AES-256 session key encrypted with RSA-OAEP
        [ 12 B ]  nonce         — random GCM nonce (96 bits)
        [ ... B]  ciphertext    — AES-256-GCM output with 128-bit tag appended

    Raises:
        FileNotFoundError: if the public key PEM file does not exist.
    """
    if not Path(public_key_path).exists():
        raise FileNotFoundError(f"Public key not found: {public_key_path}")

    aes_key: bytes = os.urandom(_AES_KEY_BYTES)
    nonce: bytes = os.urandom(_GCM_NONCE_BYTES)
    ciphertext_tag: bytes = AESGCM(aes_key).encrypt(nonce, plaintext, None)

    rsa_blob: bytes = load_public_key(public_key_path).encrypt(aes_key, _OAEP)
    rsa_blob_len_header: bytes = struct.pack(">I", len(rsa_blob))

    return rsa_blob_len_header + rsa_blob + nonce + ciphertext_tag


def decrypt_payload(encrypted_blob: bytes, private_key_path: str) -> bytes:
    """
    Reverse hybrid decryption: RSA-OAEP key unwrap → AES-256-GCM authenticated decrypt.

    Raises:
        FileNotFoundError: if the private key PEM file does not exist.
        ValueError: on authentication failure, structural corruption, or key mismatch.
                    All failure modes raise ValueError so callers need only one handler.
    """
    if not Path(private_key_path).exists():
        raise FileNotFoundError(f"Private key not found: {private_key_path}")
    if len(encrypted_blob) < 4:
        raise ValueError("Blob is too short to contain a valid BARACK-Protect header.")

    rsa_blob_len: int = struct.unpack(">I", encrypted_blob[:4])[0]
    offset: int = 4

    if rsa_blob_len != _RSA_BLOB_BYTES:
        raise ValueError(
            f"Structurally invalid blob: RSA key block is {rsa_blob_len} bytes, "
            f"expected {_RSA_BLOB_BYTES} for RSA-{_RSA_KEY_BITS}."
        )

    required_min = offset + rsa_blob_len + _GCM_NONCE_BYTES + _GCM_TAG_BYTES
    if len(encrypted_blob) < required_min:
        raise ValueError(
            "Encrypted blob is truncated or structurally invalid — "
            f"expected at least {required_min} bytes, got {len(encrypted_blob)}."
        )

    rsa_blob: bytes = encrypted_blob[offset : offset + rsa_blob_len]
    offset += rsa_blob_len
    nonce: bytes = encrypted_blob[offset : offset + _GCM_NONCE_BYTES]
    offset += _GCM_NONCE_BYTES
    ciphertext_tag: bytes = encrypted_blob[offset:]

    try:
        aes_key: bytes = load_private_key(private_key_path).decrypt(rsa_blob, _OAEP)
    except Exception as exc:
        raise ValueError(
            "RSA-OAEP key unwrap failed — "
            "the blob is corrupted or the wrong private key was used."
        ) from exc

    try:
        return AESGCM(aes_key).decrypt(nonce, ciphertext_tag, None)
    except Exception as exc:
        raise ValueError(
            "AES-GCM authentication tag mismatch — "
            "payload is tampered, or the wrong private key was used."
        ) from exc


def get_key_fingerprint(public_key_path: str) -> str:
    """
    Compute the SHA-256 fingerprint of the DER-encoded SubjectPublicKeyInfo blob.
    Returns lowercase hex string (64 characters).
    """
    pub_key = load_public_key(public_key_path)
    der_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256(), backend=_BACKEND)
    digest.update(der_bytes)
    return digest.finalize().hex()
