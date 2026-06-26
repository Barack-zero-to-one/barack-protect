"""
BARACK-Protect — LSB Steganographic Engine
Deterministic Least Significant Bit injection and extraction using Pillow.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import List

from PIL import Image

_HEADER_BYTES: int = 4   # uint32 big-endian: byte count of the embedded payload
_CHANNELS: int = 3       # RGB — one LSB harvested per channel per pixel


def _capacity_bytes(width: int, height: int) -> int:
    """Maximum payload bytes storable in an image of given dimensions."""
    return (width * height * _CHANNELS) // 8 - _HEADER_BYTES


def _to_bits(data: bytes) -> List[int]:
    """Unpack bytes into a flat list of bits, MSB first within each byte."""
    bits: List[int] = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def _from_bits(bits: List[int]) -> bytes:
    """Pack a flat list of bits (MSB first) back into whole bytes."""
    result = bytearray()
    aligned_len = len(bits) - (len(bits) % 8)
    for i in range(0, aligned_len, 8):
        val = 0
        for bit in bits[i : i + 8]:
            val = (val << 1) | bit
        result.append(val)
    return bytes(result)


def _harvest_lsb(pixels: List, start_bit: int, count: int) -> List[int]:
    """
    Read `count` LSBs from the flat channel stream starting at absolute
    channel offset `start_bit`.

    Channel ordering: pixel[0].R, pixel[0].G, pixel[0].B, pixel[1].R, …
    """
    harvested: List[int] = []
    cursor = start_bit
    total_channels = len(pixels) * _CHANNELS
    while len(harvested) < count and cursor < total_channels:
        pixel_idx = cursor // _CHANNELS
        channel = cursor % _CHANNELS
        harvested.append(pixels[pixel_idx][channel] & 1)
        cursor += 1
    return harvested


def inject_secret_into_image(
    cover_image_path: str,
    payload_bytes: bytes,
    output_image_path: str,
) -> None:
    """
    Embed payload_bytes into the cover image via sequential LSB substitution.

    Pixel channel stream layout (row-major, R → G → B per pixel):
        bits [0 .. 31]   → 4-byte big-endian uint32 payload length header
        bits [32 .. end] → payload content, MSB first per byte

    Only the Least Significant Bit of each colour channel is modified;
    the remaining 7 bits of every channel are preserved, making the
    modification statistically imperceptible to the human visual system.
    Output is always written as lossless PNG to preserve the embedded bits
    against compression artefacts.

    Args:
        cover_image_path:  Path to the carrier image (PNG, JPG, BMP, etc.).
        payload_bytes:     The raw encrypted blob to conceal.
        output_image_path: Destination path for the steganographic PNG.

    Raises:
        FileNotFoundError: if the cover image does not exist.
        ValueError:        if the payload exceeds the image's LSB capacity.
    """
    cover = Path(cover_image_path)
    if not cover.exists():
        raise FileNotFoundError(f"Cover image not found: {cover_image_path}")

    img: Image.Image = Image.open(cover).convert("RGB")
    width, height = img.size
    capacity = _capacity_bytes(width, height)

    if len(payload_bytes) > capacity:
        raise ValueError(
            f"Payload ({len(payload_bytes):,} bytes) exceeds image capacity "
            f"({capacity:,} bytes). Use a larger cover image."
        )

    header: bytes = struct.pack(">I", len(payload_bytes))
    bitstream: List[int] = _to_bits(header + payload_bytes)

    pixels: List[List[int]] = [list(px) for px in img.getdata()]

    for bit_idx, bit in enumerate(bitstream):
        pixel_idx = bit_idx // _CHANNELS
        channel = bit_idx % _CHANNELS
        pixels[pixel_idx][channel] = (pixels[pixel_idx][channel] & 0xFE) | bit

    out_img: Image.Image = Image.new("RGB", (width, height))
    out_img.putdata([tuple(px) for px in pixels])  # type: ignore[arg-type]

    out_path = Path(output_image_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_img.save(str(out_path), format="PNG")


def extract_secret_from_image(stego_image_path: str) -> bytes:
    """
    Harvest the LSB of each pixel channel to reconstruct the encrypted payload.

    Reads the 32-bit length header from the first 32 channel LSBs, then
    extracts exactly payload_length × 8 subsequent LSBs.

    Args:
        stego_image_path: Path to the steganographic PNG produced by
                          inject_secret_into_image.

    Returns:
        The raw encrypted blob (bytes) ready for decryption via crypto_core.

    Raises:
        FileNotFoundError: if the stego image does not exist.
        ValueError:        if the embedded length is zero, exceeds capacity,
                           or the image is structurally too small.
    """
    stego = Path(stego_image_path)
    if not stego.exists():
        raise FileNotFoundError(f"Stego image not found: {stego_image_path}")

    img: Image.Image = Image.open(stego).convert("RGB")
    width, height = img.size
    pixels: List = list(img.getdata())

    header_bits = _harvest_lsb(pixels, 0, _HEADER_BYTES * 8)
    if len(header_bits) < _HEADER_BYTES * 8:
        raise ValueError(
            "Image is too small to contain a BARACK-Protect payload header."
        )

    payload_length: int = struct.unpack(">I", _from_bits(header_bits))[0]
    capacity = _capacity_bytes(width, height)

    if payload_length == 0:
        raise ValueError(
            "Embedded length header is zero — this image contains no hidden payload."
        )
    if payload_length > capacity:
        raise ValueError(
            f"Declared payload length ({payload_length:,} bytes) exceeds image "
            f"capacity ({capacity:,} bytes). "
            "This image was not encoded with BARACK-Protect."
        )

    payload_bits = _harvest_lsb(pixels, _HEADER_BYTES * 8, payload_length * 8)
    if len(payload_bits) < payload_length * 8:
        raise ValueError(
            "Stego image is truncated — could not extract the full payload."
        )

    return _from_bits(payload_bits)
