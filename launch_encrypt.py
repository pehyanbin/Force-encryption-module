#!/usr/bin/env python3
"""
Interactive launcher for encrypt_folder.py.

Place this script in the SAME directory as encrypt_folder.py, or pass
--tool /path/to/encrypt_folder.py when running it.

Usage:
    python launch_encrypt.py
    python launch_encrypt.py --tool /path/to/encrypt_folder.py
"""

import argparse
import getpass
import subprocess
import sys
from pathlib import Path

TOOL_NAME = "encrypt_folder.py"


# ---------------------------------------------------------------------------
# Locate the underlying tool
# ---------------------------------------------------------------------------
def find_tool(explicit: str | None = None) -> Path:
    """Return the Path to encrypt_folder.py, or exit with a helpful error."""
    if explicit:
        tool = Path(explicit).expanduser().resolve()
        if tool.is_file():
            return tool
        sys.exit(f"ERROR: tool not found at {tool}")

    for candidate in (
        Path(__file__).resolve().parent / TOOL_NAME,
        Path.cwd() / TOOL_NAME,
    ):
        if candidate.is_file():
            return candidate

    sys.exit(
        f"ERROR: could not find '{TOOL_NAME}'.\n"
        f"       Put this script in the same folder as {TOOL_NAME}, "
        f"or run with --tool /path/to/{TOOL_NAME}"
    )


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------
def ask_folder() -> Path:
    """Prompt for a folder path until a valid directory is supplied."""
    while True:
        raw = input("Folder to encrypt: ").strip().strip('"').strip("'")
        if not raw:
            print("  [x] path cannot be empty, try again.")
            continue

        folder = Path(raw).expanduser()
        if not folder.exists():
            print(f"  [x] not found: {folder}")
            continue
        if not folder.is_dir():
            print(f"  [x] not a directory: {folder}")
            continue
        return folder


def ask_password() -> str:
    """Prompt for a password twice and confirm they match (hidden input)."""
    while True:
        pw1 = getpass.getpass("Password: ")
        if not pw1:
            print("  [x] password cannot be empty.")
            continue
        pw2 = getpass.getpass("Confirm password: ")
        if pw1 != pw2:
            print("  [x] passwords do not match, try again.")
            continue
        return pw1


def ask_yes_no(question: str, default: bool = False) -> bool:
    suffix = " [Y/n] " if default else " [y/N] "
    answer = input(question + suffix).strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes")


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
def run(tool: Path, folder: Path, password: str, delete: bool) -> int:
    cmd = [sys.executable, str(tool), str(folder), password]
    if delete:
        cmd.append("--delete")

    print("\nRunning:")
    display = " ".join("********" if part == password else part for part in cmd)
    print("  " + display + "\n")

    try:
        return subprocess.call(cmd)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description=f"Interactive launcher for {TOOL_NAME}"
    )
    parser.add_argument(
        "--tool",
        help=f"Path to {TOOL_NAME} (default: look next to this script)",
        default=None,
    )
    args = parser.parse_args()

    tool = find_tool(args.tool)

    print(f"\n=== Folder Encryption ({TOOL_NAME}) ===")
    folder = ask_folder()
    delete = ask_yes_no(
        "Delete original files after successful encryption?", default=False
    )
    password = ask_password()

    print("\nSummary")
    print(f"  folder : {folder}")
    print(f"  delete : {delete}")

    if not ask_yes_no("Proceed?", default=True):
        print("Cancelled.")
        sys.exit(0)

    rc = run(tool, folder, password, delete)
    if rc == 0:
        print("\n✔ Done.")
    else:
        print(f"\n✘ {TOOL_NAME} exited with code {rc}.")
    sys.exit(rc)


if __name__ == "__main__":
    main()