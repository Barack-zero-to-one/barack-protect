"""
BARACK-Protect — Fragment Engine
XOR-based N-of-N secret sharing for distributed steganographic channels.
"""

from __future__ import annotations

import os
import struct
import uuid
from typing import List, Tuple


_PACKET_HEADER_SIZE: int = 22   # 16B session_id + 1B index + 1B total + 4B data_len


def generate_session_id() -> bytes:
    """Generate a cryptographically random 16-byte session identifier."""
    return uuid.uuid4().bytes


def format_session_id(session_id: bytes) -> str:
    """Return the session ID as a 32-character uppercase hex string."""
    return session_id.hex().upper()


def parse_session_id(hex_str: str) -> bytes:
    """Parse a hex session ID string back to bytes.

    Raises:
        ValueError: if the string is not valid hex or not 32 hex characters.
    """
    clean = hex_str.strip().replace(" ", "").replace(":", "").upper()
    if len(clean) != 32:
        raise ValueError(
            f"Session ID must be 32 hex characters, got {len(clean)}."
        )
    return bytes.fromhex(clean)


def split_into_shares(data: bytes, n: int) -> List[bytes]:
    """
    XOR N-of-N secret sharing.

    Produces N shares of identical length to the input. ALL N shares are
    required for reconstruction. Possessing any strict subset of shares
    reveals zero information about the original data — information-theoretic
    security equivalent to a one-time pad.

    Algorithm:
        shares[0..N-2] = N-1 independent random byte strings
        shares[N-1]    = XOR of all previous shares with the original data

    Args:
        data: The byte sequence to protect.
        n:    Number of shares (2 ≤ n ≤ 255).

    Raises:
        ValueError: if n is out of range or data is empty.
    """
    if not 2 <= n <= 255:
        raise ValueError(f"Share count must be between 2 and 255, got {n}.")
    if not data:
        raise ValueError("Cannot split empty data.")

    random_shares: List[bytes] = [os.urandom(len(data)) for _ in range(n - 1)]

    last = bytearray(data)
    for share in random_shares:
        for i, byte in enumerate(share):
            last[i] ^= byte

    return random_shares + [bytes(last)]


def reconstruct_from_shares(shares: List[bytes]) -> bytes:
    """
    Reconstruct the original secret by XOR-ing all N shares together.

    Raises:
        ValueError: if no shares are provided, or shares have inconsistent lengths.
    """
    if not shares:
        raise ValueError("No shares provided for reconstruction.")

    lengths = {len(s) for s in shares}
    if len(lengths) != 1:
        raise ValueError(
            f"All shares must be equal length. Found sizes: {sorted(lengths)}."
        )

    result = bytearray(shares[0])
    for share in shares[1:]:
        for i, byte in enumerate(share):
            result[i] ^= byte
    return bytes(result)


def pack_fragment_packet(
    session_id: bytes,
    index: int,
    total: int,
    share_data: bytes,
) -> bytes:
    """
    Pack fragment metadata and share bytes into a single sequence ready for
    embedding into a cover image via stego_engine.

    Wire layout:
        [16 B] session_id       — random UUID identifying the session
        [ 1 B] fragment index   — 0-based position of this share
        [ 1 B] total N          — total number of shares in the session
        [ 4 B] share data len   — big-endian uint32
        [ N B] share data       — the XOR share bytes

    Raises:
        ValueError: if session_id is not 16 bytes, or index/total are invalid.
    """
    if len(session_id) != 16:
        raise ValueError("session_id must be exactly 16 bytes.")
    if not (0 <= index < total <= 255):
        raise ValueError(f"Invalid fragment index/total: {index}/{total}.")
    return (
        session_id
        + bytes([index, total])
        + struct.pack(">I", len(share_data))
        + share_data
    )


def unpack_fragment_packet(raw: bytes) -> Tuple[bytes, int, int, bytes]:
    """
    Unpack a fragment packet extracted from a steganographic image.

    Returns:
        (session_id: bytes, index: int, total: int, share_data: bytes)

    Raises:
        ValueError: if the packet is too short or the declared length is inconsistent.
    """
    if len(raw) < _PACKET_HEADER_SIZE:
        raise ValueError(
            f"Fragment packet too short: {len(raw)} bytes, "
            f"minimum is {_PACKET_HEADER_SIZE}."
        )
    session_id = raw[:16]
    index = raw[16]
    total = raw[17]
    data_len: int = struct.unpack(">I", raw[18:22])[0]
    end = _PACKET_HEADER_SIZE + data_len
    if len(raw) < end:
        raise ValueError(
            f"Fragment packet data truncated: expected {end} bytes, got {len(raw)}."
        )
    return session_id, index, total, raw[_PACKET_HEADER_SIZE:end]
