"""
BARACK-Protect — Unified Console Orchestrator
Interactive ANSI-colored CLI for steganographic data vault operations.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

try:
    from crypto_core import (
        decrypt_payload,
        encrypt_payload,
        generate_rsa_keypair,
        get_key_fingerprint,
    )
    from stego_engine import extract_secret_from_image, inject_secret_into_image
except ImportError as exc:
    print(f"\n[FATAL] Missing dependency: {exc}")
    print("Install requirements:  pip install cryptography Pillow")
    sys.exit(1)

# Enable ANSI escape processing on Windows 10+
if sys.platform == "win32":
    os.system("")

# ── Colour palette ─────────────────────────────────────────────────────────────
G    = "\033[92m"    # bright green
DG   = "\033[32m"    # dark green
Y    = "\033[93m"    # bright yellow
R    = "\033[91m"    # bright red
C    = "\033[96m"    # cyan
W    = "\033[97m"    # bright white
DIM  = "\033[2m"     # dimmed
RST  = "\033[0m"     # full reset
BOLD = "\033[1m"     # bold

# ── Default key locations ──────────────────────────────────────────────────────
_KEYS_DIR = Path.home() / ".barack_protect"
_PRIV_KEY = _KEYS_DIR / "private_key.pem"
_PUB_KEY  = _KEYS_DIR / "public_key.pem"

# ── Giant ASCII art banner ─────────────────────────────────────────────────────
_BANNER = (
    f"{BOLD}{G}\n"
    "  ██████╗  █████╗ ██████╗  █████╗  ██████╗██╗  ██╗\n"
    "  ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██║ ██╔╝\n"
    "  ██████╔╝███████║██████╔╝███████║██║     █████╔╝ \n"
    "  ██╔══██╗██╔══██║██╔══██╗██╔══██║██║     ██╔═██╗ \n"
    "  ██████╔╝██║  ██║██║  ██║██║  ██║╚██████╗██║  ██╗\n"
    f"  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝{RST}\n"
    f"{BOLD}{G}"
    "  ██████╗ ██████╗  ██████╗ ████████╗███████╗ ██████╗████████╗\n"
    "  ██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝\n"
    "  ██████╔╝██████╔╝██║   ██║   ██║   █████╗  ██║        ██║   \n"
    "  ██╔═══╝ ██╔══██╗██║   ██║   ██║   ██╔══╝  ██║        ██║   \n"
    "  ██║     ██║  ██║╚██████╔╝   ██║   ███████╗╚██████╗   ██║   \n"
    f"  ╚═╝     ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝ ╚═════╝   ╚═╝{RST}\n"
    f"\n{BOLD}{G}"
    "  ╔═══════════════════════════════════════════════════════════════╗\n"
    "  ║   ⚡   CODED BY BARACK OS  ·  Steganographic Vault  ⚡       ║\n"
    "  ║        AES-256-GCM  ·  RSA-2048-OAEP  ·  LSB Pixel Matrix   ║\n"
    f"  ╚═══════════════════════════════════════════════════════════════╝{RST}\n"
)


# ── Utility helpers ────────────────────────────────────────────────────────────

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
    except (KeyboardInterrupt, EOFError):
        print()
        return default
    return raw if raw else default


def _pause() -> None:
    try:
        input(f"\n  {DIM}Appuyez sur ENTRÉE pour retourner au menu principal…{RST}")
    except (KeyboardInterrupt, EOFError):
        pass


def _show_banner() -> None:
    _clear()
    print(_BANNER)


def _print_menu() -> None:
    print(f"  {BOLD}{W}{'━' * 60}{RST}")
    print(f"  {BOLD}{C}    SYSTÈME DE PROTECTION — MENU PRINCIPAL{RST}")
    print(f"  {BOLD}{W}{'━' * 60}{RST}\n")
    print(f"    {BOLD}{Y}1){RST}  {G}🔐{RST}  Chiffrer et Dissimuler un Secret dans une Image")
    print(f"    {BOLD}{Y}2){RST}  {G}🔓{RST}  Extraire et Déchiffrer un Secret depuis une Image")
    print(f"    {BOLD}{Y}3){RST}  {G}⚙️ {RST}   Générer / Vérifier mes Clés d'Identité RSA-2048")
    print(f"    {BOLD}{Y}4){RST}  {R}❌{RST}  Quitter le Système de Protection")
    print()


# ── Option 1 — Encode ─────────────────────────────────────────────────────────

def _flow_encode() -> None:
    _show_banner()
    print(f"  {BOLD}{G}[ MODE ENCODAGE — CHIFFREMENT & DISSIMULATION ]{RST}\n")
    _hr()

    _log("INFO", "Sélectionnez la source du secret à dissimuler:")
    print(f"\n    {Y}1){RST}  Saisir un texte directement")
    print(f"    {Y}2){RST}  Charger depuis un fichier binaire\n")
    src_choice = _prompt("Choix (1 ou 2)", "1")

    secret_bytes: bytes
    if src_choice == "2":
        src_path_str = _prompt("Chemin vers le fichier secret")
        if not src_path_str:
            _log("ERR", "Chemin du fichier non fourni.")
            _pause()
            return
        src_path = Path(src_path_str)
        if not src_path.exists():
            _log("ERR", f"Fichier introuvable: {src_path_str}")
            _pause()
            return
        secret_bytes = src_path.read_bytes()
        _log("OK", f"Fichier chargé — {len(secret_bytes):,} octets")
    else:
        text_input = _prompt("Saisissez votre secret (texte libre)")
        if not text_input:
            _log("ERR", "Le secret ne peut pas être vide.")
            _pause()
            return
        secret_bytes = text_input.encode("utf-8")
        _log("OK", f"Texte capturé — {len(secret_bytes):,} octets")

    _hr()

    cover_path_str = _prompt("Chemin de l'image de couverture (PNG / JPG / BMP)")
    if not cover_path_str or not Path(cover_path_str).exists():
        _log("ERR", f"Image de couverture introuvable: {cover_path_str!r}")
        _pause()
        return

    cover_stem = Path(cover_path_str).stem
    default_output = str(
        Path(cover_path_str).with_name(f"{cover_stem}_stego.png")
    )
    output_path_str = _prompt("Chemin de l'image de sortie (PNG)", default_output)
    if not output_path_str:
        _log("ERR", "Chemin de sortie non fourni.")
        _pause()
        return

    pub_key_str = _prompt("Chemin de la clé publique RSA", str(_PUB_KEY))
    if not Path(pub_key_str).exists():
        _log("ERR", f"Clé publique introuvable: {pub_key_str}")
        _log("WARN", "Exécutez l'option 3 pour générer vos clés d'identité.")
        _pause()
        return

    _hr()
    _log("PROC", "Chiffrement AES-256-GCM + RSA-2048-OAEP en cours…")
    try:
        encrypted_blob = encrypt_payload(secret_bytes, pub_key_str)
    except Exception as exc:
        _log("ERR", f"Échec du chiffrement: {exc}")
        _pause()
        return

    _log("OK", f"Payload chiffré — {len(encrypted_blob):,} octets générés")
    _log("PROC", "Injection LSB dans la matrice de pixels en cours…")

    try:
        inject_secret_into_image(cover_path_str, encrypted_blob, output_path_str)
    except ValueError as exc:
        _log("ERR", f"Capacité insuffisante: {exc}")
        _pause()
        return
    except Exception as exc:
        _log("ERR", f"Erreur d'injection: {exc}")
        _pause()
        return

    pixels_used = (len(encrypted_blob) + 4) * 8 // 3
    _hr()
    _log("OK", "Image stéganographique générée avec succès!")
    print(f"\n  {G}  Fichier de sortie    : {BOLD}{output_path_str}{RST}")
    print(f"  {G}  Secret original      : {len(secret_bytes):,} octets{RST}")
    print(f"  {G}  Payload chiffré      : {len(encrypted_blob):,} octets{RST}")
    print(f"  {G}  Pixels LSB modifiés  : ~{pixels_used:,}{RST}")
    print(f"  {G}  Algorithme crypto    : AES-256-GCM + RSA-2048-OAEP{RST}")
    _pause()


# ── Option 2 — Decode ─────────────────────────────────────────────────────────

def _flow_decode() -> None:
    _show_banner()
    print(f"  {BOLD}{G}[ MODE DÉCODAGE — EXTRACTION & DÉCHIFFREMENT ]{RST}\n")
    _hr()

    stego_path_str = _prompt("Chemin de l'image stéganographique")
    if not stego_path_str or not Path(stego_path_str).exists():
        _log("ERR", f"Image introuvable: {stego_path_str!r}")
        _pause()
        return

    priv_key_str = _prompt("Chemin de la clé privée RSA", str(_PRIV_KEY))
    if not Path(priv_key_str).exists():
        _log("ERR", f"Clé privée introuvable: {priv_key_str}")
        _log("WARN", "Exécutez l'option 3 pour générer vos clés d'identité.")
        _pause()
        return

    _hr()
    _log("PROC", "Extraction LSB depuis la matrice de pixels…")
    try:
        encrypted_blob = extract_secret_from_image(stego_path_str)
    except ValueError as exc:
        _log("ERR", f"Aucun payload BARACK-Protect détecté: {exc}")
        _pause()
        return
    except Exception as exc:
        _log("ERR", f"Erreur d'extraction inattendue: {exc}")
        _pause()
        return

    _log("OK", f"Payload extrait — {len(encrypted_blob):,} octets chiffrés")
    _log("PROC", "Déchiffrement RSA-OAEP + AES-256-GCM en cours…")

    try:
        plaintext = decrypt_payload(encrypted_blob, priv_key_str)
    except ValueError as exc:
        _log("ERR", f"Échec du déchiffrement: {exc}")
        _log("WARN", "Assurez-vous d'utiliser la clé privée correspondant à la clé d'encodage.")
        _pause()
        return
    except Exception as exc:
        _log("ERR", f"Erreur inattendue lors du déchiffrement: {exc}")
        _pause()
        return

    _log("OK", f"Déchiffrement réussi — {len(plaintext):,} octets récupérés")
    _hr()

    print(f"\n    {Y}1){RST}  Afficher le secret comme texte UTF-8")
    print(f"    {Y}2){RST}  Enregistrer en fichier binaire\n")
    out_choice = _prompt("Que faire avec le secret récupéré?", "1")

    if out_choice == "2":
        out_path_str = _prompt("Chemin du fichier de sortie")
        if not out_path_str:
            _log("ERR", "Chemin de sortie non fourni.")
            _pause()
            return
        try:
            Path(out_path_str).write_bytes(plaintext)
            _log("OK", f"Secret enregistré: {out_path_str}  ({len(plaintext):,} octets)")
        except Exception as exc:
            _log("ERR", f"Impossible d'écrire le fichier: {exc}")
    else:
        _hr()
        try:
            decoded_text = plaintext.decode("utf-8")
            print(f"\n  {BOLD}{G}SECRET RÉCUPÉRÉ:{RST}")
            _hr(56)
            for line in decoded_text.splitlines():
                print(f"  {W}{line}{RST}")
            _hr(56)
        except UnicodeDecodeError:
            _log("WARN", "Le payload ne semble pas être du texte UTF-8.")
            _log("INFO", "Représentation hexadécimale (256 premiers octets):")
            hex_preview = plaintext[:256].hex()
            chunks = [hex_preview[i:i+32] for i in range(0, len(hex_preview), 32)]
            for chunk in chunks:
                print(f"  {DG}{chunk}{RST}")

    _pause()


# ── Option 3 — Keys ───────────────────────────────────────────────────────────

def _flow_keys() -> None:
    _show_banner()
    print(f"  {BOLD}{G}[ GESTION DES CLÉS D'IDENTITÉ RSA-2048 ]{RST}\n")
    _hr()

    keys_exist = _PRIV_KEY.exists() and _PUB_KEY.exists()

    if keys_exist:
        _log("OK", f"Paire de clés détectée dans: {_KEYS_DIR}")
        try:
            raw_fp = get_key_fingerprint(str(_PUB_KEY))
            segments = [raw_fp[i:i+4] for i in range(0, len(raw_fp), 4)]
            formatted = ":".join(segments)
            print(f"\n  {C}  Empreinte publique SHA-256:{RST}")
            print(f"  {BOLD}{G}  {formatted}{RST}\n")
        except Exception as exc:
            _log("WARN", f"Impossible de lire l'empreinte: {exc}")
        print(f"  {DIM}  Clé privée  → {_PRIV_KEY}{RST}")
        print(f"  {DIM}  Clé publique → {_PUB_KEY}{RST}\n")
    else:
        _log("WARN", "Aucune paire de clés trouvée à l'emplacement par défaut.")
        _log("INFO", f"Emplacement par défaut: {_KEYS_DIR}")
        print()

    _hr()
    print(f"\n    {Y}1){RST}  Générer une nouvelle paire RSA-2048 (emplacement par défaut)")
    print(f"    {Y}2){RST}  Générer vers un emplacement personnalisé")
    print(f"    {Y}3){RST}  Retourner au menu principal\n")
    choice = _prompt("Choix", "3")

    if choice == "3":
        return

    if choice == "2":
        priv_str = _prompt("Chemin pour la clé privée (.pem)")
        pub_str  = _prompt("Chemin pour la clé publique (.pem)")
        if not priv_str or not pub_str:
            _log("ERR", "Les deux chemins sont requis.")
            _pause()
            return
        priv_path, pub_path = Path(priv_str), Path(pub_str)
    else:
        priv_path, pub_path = _PRIV_KEY, _PUB_KEY

    if priv_path.exists() or pub_path.exists():
        confirm = _prompt(
            f"{Y}ATTENTION{RST} — Des clés existent déjà ici. Écraser? (oui / non)",
            "non",
        )
        if confirm.lower() not in ("oui", "o", "yes", "y"):
            _log("INFO", "Opération annulée — clés existantes conservées.")
            _pause()
            return

    _log("PROC", "Génération RSA-2048 en cours (cela peut prendre quelques secondes)…")
    t0 = time.monotonic()
    try:
        priv_path.parent.mkdir(parents=True, exist_ok=True)
        pub_path.parent.mkdir(parents=True, exist_ok=True)
        generate_rsa_keypair(str(priv_path), str(pub_path))
    except Exception as exc:
        _log("ERR", f"Échec de la génération: {exc}")
        _pause()
        return

    elapsed = time.monotonic() - t0
    _log("OK", f"Paire RSA-2048 générée en {elapsed:.2f}s")

    try:
        raw_fp = get_key_fingerprint(str(pub_path))
        segments = [raw_fp[i:i+4] for i in range(0, len(raw_fp), 4)]
        formatted = ":".join(segments)
        print(f"\n  {C}  Empreinte publique SHA-256:{RST}")
        print(f"  {BOLD}{G}  {formatted}{RST}")
    except Exception:
        pass

    print(f"\n  {DIM}  Clé privée  → {priv_path}{RST}")
    print(f"  {DIM}  Clé publique → {pub_path}{RST}")
    _log("WARN", "Protégez votre clé privée — elle est le seul moyen de déchiffrer vos secrets!")
    _pause()


# ── Main event loop ───────────────────────────────────────────────────────────

def main() -> None:
    handlers = {
        "1": _flow_encode,
        "2": _flow_decode,
        "3": _flow_keys,
    }

    while True:
        _show_banner()
        _print_menu()

        try:
            choice = _prompt("Votre choix (1-4)").strip()
        except (KeyboardInterrupt, EOFError):
            choice = "4"

        if choice == "4":
            _clear()
            print(f"\n  {BOLD}{G}BARACK-Protect — Système arrêté proprement. À bientôt.{RST}\n")
            sys.exit(0)

        handler = handlers.get(choice)
        if handler is None:
            _log("WARN", "Option invalide — saisissez 1, 2, 3 ou 4.")
            time.sleep(1.2)
            continue

        handler()


if __name__ == "__main__":
    main()
