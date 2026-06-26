"""
BARACK-Protect — Channel Layer
Local filesystem channel for posting and retrieving steganographic image fragments.

The LocalChannel class simulates a public image hosting platform: each "post"
is a PNG saved to a shared folder.  A social-media plugin could replace this
class with one that uploads to Twitter/Telegram while keeping the same interface.
"""

from __future__ import annotations

import math
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from PIL import Image

from fragment_engine import format_session_id, unpack_fragment_packet
from stego_engine import extract_secret_from_image, inject_secret_into_image


_COVER_PADDING_FACTOR: float = 1.4   # generate covers 40% larger than the minimum


def generate_cover_image(output_path: str, payload_size_bytes: int) -> None:
    """
    Generate a random RGB noise image large enough to hide payload_size_bytes.

    Accounts for the 4-byte stego length header used by stego_engine internally.
    The 40% padding buffer prevents edge-case off-by-one failures.

    The image is filled with cryptographically random pixel data, making its
    LSB distribution statistically uniform — a valid cover for steganography.

    Args:
        output_path:       Destination PNG path.
        payload_size_bytes: Number of bytes to embed (fragment packet size,
                            NOT including the stego header — this function
                            adds that overhead internally).
    """
    total_bits = (payload_size_bytes + 4) * 8   # +4 for stego length header
    total_pixels = math.ceil(total_bits / 3 * _COVER_PADDING_FACTOR)
    side = max(32, math.ceil(math.sqrt(total_pixels)))

    raw = os.urandom(side * side * 3)
    pixels: List[Tuple[int, int, int]] = [
        (raw[i], raw[i + 1], raw[i + 2])
        for i in range(0, side * side * 3, 3)
    ]
    img = Image.new("RGB", (side, side))
    img.putdata(pixels)  # type: ignore[arg-type]

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    img.save(str(out), format="PNG")


class LocalChannel:
    """
    Local filesystem channel that stores steganographic fragment images
    in a designated directory, simulating a public image hosting platform.

    Image naming convention:
        BARACK_{SESSION_PREFIX_8}_{INDEX:03d}.png

    where SESSION_PREFIX_8 is the first 8 hex characters of the session ID.
    This prefix is only used for fast filename-level pre-filtering; the full
    session ID inside each fragment packet is the authoritative identifier.
    """

    def __init__(self, folder: str) -> None:
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)

    def post_fragment(
        self,
        cover_image_path: str,
        fragment_packet: bytes,
        session_id_hex: str,
        index: int,
    ) -> str:
        """
        Embed fragment_packet into a cover image and save it to the channel folder.

        Args:
            cover_image_path: Path to the carrier (cover) image.
            fragment_packet:  Raw bytes from pack_fragment_packet().
            session_id_hex:   32-char uppercase hex session ID.
            index:            0-based fragment index.

        Returns:
            Absolute path of the published image file.
        """
        filename = f"BARACK_{session_id_hex[:8]}_{index:03d}.png"
        output_path = str(self.folder / filename)
        inject_secret_into_image(cover_image_path, fragment_packet, output_path)
        return output_path

    def scan_session(
        self, session_id_hex: str
    ) -> Tuple[Dict[int, bytes], Optional[int]]:
        """
        Scan the channel folder for all images belonging to a session.

        Only files whose embedded session ID matches exactly (full 32 hex chars)
        are accepted.  Non-image files and unrelated stego images are silently
        skipped.

        Returns:
            (found_shares, expected_total) where:
                found_shares   — dict mapping fragment index → share_data bytes
                expected_total — the N declared in the fragment header, or None
                                 if no valid fragments were found for this session
        """
        target = session_id_hex.strip().upper()
        prefix = f"BARACK_{target[:8]}_"
        found: Dict[int, bytes] = {}
        expected_total: Optional[int] = None

        for img_path in sorted(self.folder.glob("BARACK_*.png")):
            if not img_path.name.startswith(prefix):
                continue
            try:
                raw = extract_secret_from_image(str(img_path))
                sid_bytes, index, total, share_data = unpack_fragment_packet(raw)
                if format_session_id(sid_bytes) != target:
                    continue
                if expected_total is None:
                    expected_total = total
                elif expected_total != total:
                    continue   # inconsistent header — skip this fragment silently
                found[index] = share_data
            except Exception:
                continue   # not a BARACK fragment — skip

        return found, expected_total

    def list_sessions(self) -> List[str]:
        """
        Return all unique 8-character session prefixes found in the channel.

        These prefixes can be used to browse available sessions before the
        user supplies a full session ID.
        """
        seen: set[str] = set()
        for img_path in self.folder.glob("BARACK_*.png"):
            parts = img_path.stem.split("_")
            if len(parts) >= 2:
                seen.add(parts[1])
        return sorted(seen)
