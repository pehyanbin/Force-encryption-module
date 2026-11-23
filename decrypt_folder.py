#!/usr/bin/env python3
"""
Folder Decryption Tool (decrypt only)

Recursively decrypts every '.enc' file in a folder. Files must have been
created by encrypt_folder.py (or a compatible tool using the same format).

pip install cryptography

Usage:
    python decrypt_folder.py <folder> <password> [--delete]
"""

import sys
import argparse
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Constants (must match encrypt_folder.py)
SALT_SIZE = 16          # bytes
NONCE_SIZE = 12         # bytes (GCM standard)
KEY_SIZE = 32           # 256-bit key
KDF_ITERATIONS = 480_000
MAGIC = b"ENCF"         # File header magic
VERSION = b"\x01"       # File format version
ENC_EXT = ".enc"


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------
def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from password + salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


# ---------------------------------------------------------------------------
# File decryption
# ---------------------------------------------------------------------------
def decrypt_file(file_path: Path, password: str, delete_original: bool = False) -> Path:
    """Decrypt a single .enc file. Returns the path of the decrypted file."""
    if file_path.suffix != ENC_EXT:
        raise ValueError(f"Not an encrypted file (missing {ENC_EXT}): {file_path}")

    data = file_path.read_bytes()
    header_len = len(MAGIC) + len(VERSION) + SALT_SIZE + NONCE_SIZE
    if len(data) < header_len:
        raise ValueError(f"File too short / corrupt: {file_path}")

    if data[:len(MAGIC)] != MAGIC:
        raise ValueError(f"Bad magic header (not our format): {file_path}")
    pos = len(MAGIC)
    version = data[pos:pos + len(VERSION)]
    pos += len(VERSION)
    if version != VERSION:
        raise ValueError(f"Unsupported version: {version!r}")

    salt = data[pos:pos + SALT_SIZE]
    pos += SALT_SIZE
    nonce = data[pos:pos + NONCE_SIZE]
    pos += NONCE_SIZE
    ciphertext = data[pos:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise ValueError(
            f"Decryption failed (wrong password or corrupted file): {file_path}"
        ) from exc

    # Strip .enc
    out_path = file_path.with_suffix("")
    out_path.write_bytes(plaintext)

    if delete_original:
        file_path.unlink()

    print(f"  [dec] {file_path.name} -> {out_path.name}")
    return out_path


# ---------------------------------------------------------------------------
# Folder decryption
# ---------------------------------------------------------------------------
def decrypt_folder(folder: Path, password: str, delete_originals: bool = False) -> None:
    """Recursively decrypt all .enc files in a folder."""
    if not folder.is_dir():
        raise NotADirectoryError(f"Not a directory: {folder}")

    files = [p for p in folder.rglob(f"*{ENC_EXT}") if p.is_file()]
    print(f"Decrypting {len(files)} file(s) under {folder} ...")
    for f in files:
        try:
            decrypt_file(f, password, delete_original=delete_originals)
        except Exception as exc:
            print(f"  [error] {f}: {exc}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="AES-256-GCM folder decryption tool (decrypt only)"
    )
    parser.add_argument("folder", type=Path)
    parser.add_argument("password")
    parser.add_argument("--delete", action="store_true",
                        help="Delete original .enc files after successful decryption")
    args = parser.parse_args()

    try:
        decrypt_folder(args.folder, args.password, args.delete)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()