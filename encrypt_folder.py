#!/usr/bin/env python3
"""
Folder Encryption Tool (encrypt only)

Recursively encrypts every file in a folder using AES-256-GCM
with PBKDF2-HMAC-SHA256 key derivation.

Encrypted files get the original filename + '.enc'.

pip install cryptography

Usage:
    python encrypt_folder.py <folder> <password> [--delete]
"""

import os
import sys
import argparse
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Constants
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
# File encryption
# ---------------------------------------------------------------------------
def encrypt_file(file_path: Path, password: str, delete_original: bool = False) -> Path:
    """Encrypt a single file. Returns the path of the encrypted file."""
    if file_path.suffix == ENC_EXT:
        print(f"  [skip] already encrypted: {file_path}")
        return file_path

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
def main():
    parser = argparse.ArgumentParser(
        description="AES-256-GCM folder encryption tool (encrypt only)"
    )
    parser.add_argument("folder", type=Path)
    parser.add_argument("password")
    parser.add_argument("--delete", action="store_true",
                        help="Delete original files after successful encryption")
    args = parser.parse_args()

    try:
        encrypt_folder(args.folder, args.password, args.delete)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()