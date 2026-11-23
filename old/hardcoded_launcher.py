#!/usr/bin/env python3
"""
Hardcoded runner for crypt_tool.py.

Edit the four CONFIG values below, then run:
    python run_crypt.py

It will call the matching crypt_tool.py command using those paths/passwords.
"""

import subprocess
import sys
from pathlib import Path

# ===========================================================================
# CONFIG — edit these four values
# ===========================================================================

# 1) Path to crypt_tool.py (leave as None to auto-detect next to this script).
TOOL_PATH = None

# 2) Single-file target used by 'encrypt' and 'decrypt'.
#    For 'encrypt', point at the plaintext file you want to encrypt.
#    For 'decrypt', point at the corresponding '.enc' file.
FILE_PATH = Path.home() / "Downloads" / "launcher-copy.py"

# 3) Folder target used by 'encrypt-folder' and 'decrypt-folder'.
FOLDER_PATH = Path.home() / "Downloads"

# 4) Password (same one used for encryption AND decryption).
PASSWORD = "password123"

# ===========================================================================
# Which command to run? Uncomment exactly ONE of the four lines below.
# ===========================================================================

COMMAND = "encrypt"          # python crypt_tool.py encrypt       <FILE_PATH>   <PASSWORD>
# COMMAND = "decrypt"        # python crypt_tool.py decrypt       <FILE_PATH>   <PASSWORD>
# COMMAND = "encrypt-folder" # python crypt_tool.py encrypt-folder <FOLDER_PATH> <PASSWORD>
# COMMAND = "decrypt-folder" # python crypt_tool.py decrypt-folder <FOLDER_PATH> <PASSWORD>

# ===========================================================================
# Runner (no need to edit below)
# ===========================================================================

def find_tool() -> Path:
    """Return the path to crypt_tool.py, or exit with an error."""
    if TOOL_PATH:
        tool = Path(TOOL_PATH).expanduser().resolve()
        if tool.is_file():
            return tool
        sys.exit(f"ERROR: crypt_tool.py not found at {tool}")

    for candidate in (
        Path(__file__).resolve().parent / "crypt_tool.py",
        Path.cwd() / "crypt_tool.py",
    ):
        if candidate.is_file():
            return candidate

    sys.exit(
        "ERROR: could not find crypt_tool.py.\n"
        "       Put it next to this script or set TOOL_PATH above."
    )


def pick_target(command: str) -> Path:
    """Return the correct target (file or folder) for the given command."""
    if command in ("encrypt", "decrypt"):
        target = FILE_PATH
    elif command in ("encrypt-folder", "decrypt-folder"):
        target = FOLDER_PATH
    else:
        sys.exit(f"ERROR: unknown command {command!r}")

    target = Path(target).expanduser()
    if not target.exists():
        sys.exit(f"ERROR: target does not exist: {target}")
    return target


def main() -> None:
    tool = find_tool()
    target = pick_target(COMMAND)

    # Build the exact command that will be run.
    cmd = [
        sys.executable,   # same Python interpreter that's running this script
        str(tool),
        COMMAND,
        str(target),
        PASSWORD,
    ]

    # Show what will be run (mask the password in the display).
    shown = " ".join("********" if part == PASSWORD else part for part in cmd)
    print("Running:")
    print("  " + shown)
    print()

    # Execute crypt_tool.py as a child process.
    try:
        rc = subprocess.call(cmd)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)

    if rc == 0:
        print("\n✔ Done.")
    else:
        print(f"\n✘ crypt_tool.py exited with code {rc}.")
    sys.exit(rc)


if __name__ == "__main__":
    main()