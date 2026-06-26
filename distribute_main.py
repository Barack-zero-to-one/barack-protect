"""
BARACK-Protect — Distributed Steganographic Orchestrator
Fragment a secret across N images using XOR N-of-N sharing, then reconstruct
from any local channel folder that holds all N published fragments.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

try:
    from channel import LocalChannel, generate_cover_image
    from crypto_core import decrypt_payload, encrypt_payload
    from fragment_engine import (
        format_session_id,
        generate_session_id,
        pack_fragment_packet,
        parse_session_id,
        reconstruct_from_shares,
        split_into_shares,
    )
except ImportError as exc:
    print(f"\n[FATAL] Module manquant: {exc}")
    print("Installez les dépendances:  pip install cryptography Pillow")
    sys.exit(1)

if sys.platform == "win32":
    os.system("")

G    = "\033[92m"
DG   = "\033[32m"
Y    = "\033[93m"
R    = "\033[91m"
C    = "\033[96m"
W    = "\033[97m"
DIM  = "\033[2m"
RST  = "\033[0m"
BOLD = "\033[1m"

_DEFAULT_KEYS_DIR = Path.home() / ".barack_protect"
_DEFAULT_PRIV_KEY = _DEFAULT_KEYS_DIR / "private_key.pem"
_DEFAULT_PUB_KEY  = _DEFAULT_KEYS_DIR / "public_key.pem"

_BANNER = f"""{BOLD}{G}
  ██████╗  █████╗ ██████╗  █████╗  ██████╗██╗  ██╗
  ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
  ██████╔╝███████║██████╔╝███████║██║     █████╔╝
  ██╔══██╗██╔══██║██╔══██╗██╔══██║██║     ██╔═██╗
  ██████╔╝██║  ██║██║  ██║██║  ██║╚██████╗██║  ██╗
  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝{RST}
{BOLD}{G}
  ██████╗ ██████╗  ██████╗ ████████╗███████╗ ██████╗████████╗
  ██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
  ██████╔╝██████╔╝██║   ██║   ██║   █████╗  ██║        ██║
  ██╔═══╝ ██╔══██╗██║   ██║   ██║   ██╔══╝  ██║        ██║
  ██║     ██║  ██║╚██████╔╝   ██║   ███████╗╚██████╗   ██║
  ╚═╝     ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝ ╚═════╝   ╚═╝{RST}

{BOLD}{G}  ╔═══════════════════════════════════════════════════════════════╗
  ║    📡  CODED BY BARACK OS  ·  RÉSEAU STÉGANOGRAPHIQUE  📡    ║
  ║     Partage XOR N-de-N  ·  LSB Matrix  ·  Canal Local        ║
  ╚═══════════════════════════════════════════════════════════════╝{RST}
"""


def _clear() -> None:
    os.system("cls" if sys.platform == "win32" else "clear")


def _log(level: str, msg: str) -> None:
    ts = time.strftime("%H:%M:%S")
    palette: dict[str, str] = {
        "INFO": C, "OK": G, "WARN": Y, "ERR": R, "PROC": DG,
    }
    col = palette.get(level, W)
    print(f"  {DIM}[{ts}]{RST} {BOLD}{col}[{level:4s}]{RST} {msg}")


def _hr(width: int = 62) -> None:
    print(f"  {DG}{'─' * width}{RST}")


def _prompt(label: str, default: str = "") -> str:
    hint = f" {DIM}[{default}]{RST}" if default else ""
    try:
        raw = input(f"  {G}❯{RST} {W}{label}{hint}: {RST}").strip()
    except EOFError:
        print()
        return default
    return raw if raw else default


def _pause() -> None:
    try:
        input(f"\n  {DIM}Appuyez sur ENTRÉE pour retourner au menu…{RST}")
    except (KeyboardInterrupt, EOFError):
        pass


def _show_banner() -> None:
    _clear()
    print(_BANNER)


def _print_menu() -> None:
    print(f"  {BOLD}{W}{'━' * 60}{RST}")
    print(f"  {BOLD}{C}    MODE DISTRIBUÉ — MENU PRINCIPAL{RST}")
    print(f"  {BOLD}{W}{'━' * 60}{RST}\n")
    print(f"    {BOLD}{Y}1){RST}  {G}📡{RST}  Distribuer un secret sur N images")
    print(f"    {BOLD}{Y}2){RST}  {G}🔄{RST}  Reconstruire un secret depuis un canal")
    print(f"    {BOLD}{Y}3){RST}  {R}❌{RST}  Quitter")
    print()


def _display_session_id(session_id_hex: str) -> None:
    parts = [session_id_hex[i : i + 8] for i in range(0, len(session_id_hex), 8)]
    formatted = "  ".join(parts)
    print(f"\n  {BOLD}{C}SESSION ID (à transmettre au destinataire):{RST}")
    print(f"\n  {BOLD}{G}  {formatted}{RST}\n")
    print(f"  {DIM}  Sans ce code, la reconstruction est impossible.{RST}")


def _flow_distribute() -> None:
    _show_banner()
    print(f"  {BOLD}{G}[ DISTRIBUER UN SECRET SUR N IMAGES ]{RST}\n")
    _hr()

    _log("INFO", "Source du secret:")
    print(f"\n    {Y}1){RST}  Texte")
    print(f"    {Y}2){RST}  Fichier\n")
    src_choice = _prompt("Choix", "1")

    secret_bytes: bytes
    if src_choice == "2":
        path_str = _prompt("Chemin du fichier")
        src_path = Path(path_str) if path_str else Path()
        if not path_str or not src_path.exists():
            _log("ERR", f"Fichier introuvable: {path_str!r}")
            _pause()
            return
        secret_bytes = src_path.read_bytes()
        _log("OK", f"Fichier chargé — {len(secret_bytes):,} octets")
    else:
        text = _prompt("Saisissez votre secret")
        if not text:
            _log("ERR", "Secret vide.")
            _pause()
            return
        secret_bytes = text.encode("utf-8")
        _log("OK", f"Texte capturé — {len(secret_bytes):,} octets")

    _hr()

    n_str = _prompt("Nombre de fragments N (2 à 10)", "5")
    try:
        n = int(n_str)
        if not 2 <= n <= 10:
            raise ValueError()
    except ValueError:
        _log("ERR", "N doit être un entier entre 2 et 10.")
        _pause()
        return

    pub_key_str = _prompt("Clé publique RSA", str(_DEFAULT_PUB_KEY))
    if not Path(pub_key_str).exists():
        _log("ERR", f"Clé publique introuvable: {pub_key_str}")
        _log("WARN", "Lancez main.py › option 3 pour générer vos clés.")
        _pause()
        return

    channel_folder = _prompt("Dossier de sortie du canal", "barack_channel")

    _log("INFO", "Images de couverture:")
    print(f"\n    {Y}1){RST}  Générer automatiquement (bruit aléatoire)")
    print(f"    {Y}2){RST}  Utiliser mes propres images\n")
    cover_mode = _prompt("Choix", "1")

    _hr()

    _log("PROC", "Chiffrement AES-256-GCM + RSA-2048-OAEP…")
    try:
        encrypted_blob = encrypt_payload(secret_bytes, pub_key_str)
    except Exception as exc:
        _log("ERR", f"Chiffrement échoué: {exc}")
        _pause()
        return
    _log("OK", f"Blob chiffré: {len(encrypted_blob):,} octets")

    _log("PROC", f"Partage XOR N-de-N en {n} fragments…")
    try:
        shares = split_into_shares(encrypted_blob, n)
    except Exception as exc:
        _log("ERR", f"Fragmentation échouée: {exc}")
        _pause()
        return
    share_size = len(shares[0])
    _log("OK", f"{n} parts générées — {share_size:,} octets chacune")

    session_id_bytes = generate_session_id()
    session_id_hex = format_session_id(session_id_bytes)

    cover_paths: list[str] = []
    if cover_mode == "2":
        print()
        for i in range(n):
            p = _prompt(f"Image de couverture {i + 1}/{n}")
            if not p or not Path(p).exists():
                _log("ERR", f"Image introuvable: {p!r}")
                _pause()
                return
            cover_paths.append(p)
    else:
        packet_size = share_size + 22   # fragment packet header = 22 bytes
        tmp_dir = Path(channel_folder) / ".covers_tmp"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        _log("PROC", f"Génération de {n} images de couverture…")
        for i in range(n):
            tmp_cover = str(tmp_dir / f"cover_{i:03d}.png")
            generate_cover_image(tmp_cover, packet_size)
            cover_paths.append(tmp_cover)
        _log("OK", "Couvertures générées")

    channel = LocalChannel(channel_folder)

    _log("PROC", "Injection et publication des fragments…")
    print()
    published: list[str] = []
    for i, (share, cover) in enumerate(zip(shares, cover_paths)):
        try:
            packet = pack_fragment_packet(session_id_bytes, i, n, share)
            path = channel.post_fragment(cover, packet, session_id_hex, i)
            published.append(path)
            _log("OK", f"Fragment {i + 1}/{n} → {Path(path).name}")
        except Exception as exc:
            _log("ERR", f"Échec fragment {i}: {exc}")
            _pause()
            return

    # clean up temp covers
    if cover_mode != "2":
        tmp_dir_path = Path(channel_folder) / ".covers_tmp"
        for p in tmp_dir_path.glob("cover_*.png"):
            p.unlink(missing_ok=True)
        try:
            tmp_dir_path.rmdir()
        except OSError:
            pass

    _hr()
    _log("OK", f"Distribution terminée — {n} images dans: {channel_folder}/")
    print()
    _display_session_id(session_id_hex)
    print(
        f"\n  {DIM}  Chaque image semble innocente. "
        f"Toutes les {n} sont requises pour reconstruire.{RST}"
    )
    _pause()


def _flow_reconstruct() -> None:
    _show_banner()
    print(f"  {BOLD}{G}[ RECONSTRUIRE UN SECRET DEPUIS UN CANAL ]{RST}\n")
    _hr()

    channel_folder = _prompt("Dossier du canal", "barack_channel")
    if not Path(channel_folder).exists():
        _log("ERR", f"Canal introuvable: {channel_folder!r}")
        _pause()
        return

    channel = LocalChannel(channel_folder)
    sessions = channel.list_sessions()
    if sessions:
        _log("INFO", f"{len(sessions)} session(s) détectée(s) dans ce canal:")
        for prefix in sessions:
            print(f"  {DG}    {prefix}...{RST}")
        print()

    session_input = _prompt("Session ID (32 caractères hex)")
    if not session_input:
        _log("ERR", "Session ID requis.")
        _pause()
        return

    try:
        session_id_bytes = parse_session_id(session_input)
        session_id_hex = format_session_id(session_id_bytes)
    except ValueError as exc:
        _log("ERR", f"Session ID invalide: {exc}")
        _pause()
        return

    priv_key_str = _prompt("Clé privée RSA", str(_DEFAULT_PRIV_KEY))
    if not Path(priv_key_str).exists():
        _log("ERR", f"Clé privée introuvable: {priv_key_str}")
        _pause()
        return

    _hr()
    _log("PROC", f"Scan du canal pour la session {session_id_hex[:8]}…")
    try:
        found_shares, expected_total = channel.scan_session(session_id_hex)
    except Exception as exc:
        _log("ERR", f"Erreur de scan: {exc}")
        _pause()
        return

    if expected_total is None or not found_shares:
        _log("ERR", "Aucun fragment trouvé pour cette session.")
        _pause()
        return

    print()
    _log("INFO", f"Fragments trouvés: {len(found_shares)}/{expected_total}")
    for i in range(expected_total):
        marker = f"{G}✓{RST}" if i in found_shares else f"{R}✗{RST}"
        print(f"      {marker}  Fragment {i}")
    print()

    if len(found_shares) < expected_total:
        missing = [i for i in range(expected_total) if i not in found_shares]
        _log("ERR", f"Fragments manquants: {missing}")
        _log("WARN", f"Il faut les {expected_total} fragments pour reconstruire.")
        _pause()
        return

    _log("PROC", "Reconstruction XOR N-de-N…")
    try:
        ordered_shares = [found_shares[i] for i in range(expected_total)]
        encrypted_blob = reconstruct_from_shares(ordered_shares)
    except Exception as exc:
        _log("ERR", f"Reconstruction échouée: {exc}")
        _pause()
        return
    _log("OK", f"Blob reconstruit: {len(encrypted_blob):,} octets")

    _log("PROC", "Déchiffrement RSA-OAEP + AES-256-GCM…")
    try:
        plaintext = decrypt_payload(encrypted_blob, priv_key_str)
    except ValueError as exc:
        _log("ERR", f"Déchiffrement échoué: {exc}")
        _pause()
        return
    _log("OK", f"Secret récupéré: {len(plaintext):,} octets")
    _hr()

    print(f"\n    {Y}1){RST}  Afficher comme texte")
    print(f"    {Y}2){RST}  Enregistrer en fichier\n")
    out_choice = _prompt("Que faire avec le secret?", "1")

    if out_choice == "2":
        out_path_str = _prompt("Chemin de sortie")
        if not out_path_str:
            _log("ERR", "Chemin non fourni.")
            _pause()
            return
        try:
            out_file = Path(out_path_str)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_bytes(plaintext)
            _log("OK", f"Secret enregistré: {out_path_str}")
        except Exception as exc:
            _log("ERR", f"Écriture impossible: {exc}")
    else:
        _hr()
        try:
            text = plaintext.decode("utf-8")
            print(f"\n  {BOLD}{G}SECRET RÉCUPÉRÉ:{RST}")
            _hr(56)
            for line in text.splitlines():
                print(f"  {W}{line}{RST}")
            _hr(56)
        except UnicodeDecodeError:
            _log("WARN", "Payload binaire — aperçu hexadécimal (256 premiers octets):")
            hex_str = plaintext[:256].hex()
            for chunk in [hex_str[i : i + 32] for i in range(0, len(hex_str), 32)]:
                print(f"  {DG}{chunk}{RST}")

    _pause()


def main() -> None:
    handlers = {"1": _flow_distribute, "2": _flow_reconstruct}

    while True:
        _show_banner()
        _print_menu()

        try:
            choice = _prompt("Votre choix (1-3)").strip()
        except KeyboardInterrupt:
            choice = "3"

        if choice == "3":
            _clear()
            print(f"\n  {BOLD}{G}BARACK-Protect Distribué — Arrêt propre.{RST}\n")
            sys.exit(0)

        handler = handlers.get(choice)
        if handler is None:
            _log("WARN", "Option invalide — saisissez 1, 2 ou 3.")
            time.sleep(1.2)
            continue

        try:
            handler()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
