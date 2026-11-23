#!/usr/bin/env python3
"""
One-shot launcher for encrypt_folder.py.
Runs with no visible console window on Windows and logs to encrypt.log.
"""

import ctypes
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# ===========================================================================
#  HARDCODED SETTINGS
# ===========================================================================
TARGET_FOLDER   = r"refresh_rate_changer"
PASSWORD        = "password"
DELETE_ORIGINAL = True
# ===========================================================================

TOOL_NAME = "encrypt_folder.py"


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


def find_tool(explicit: str | None = None) -> Path:
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


def run(tool: Path, folder: Path, password: str, delete: bool) -> int:
    cmd = [sys.executable, str(tool), str(folder), password]
    if delete:
        cmd.append("--delete")

    log_path = Path(__file__).resolve().parent / "encrypt.log"
    with open(log_path, "a", encoding="utf-8") as log:
        log.write(f"\n--- {datetime.now()} ---\n")
        log.write(f"folder: {folder}\n")
        log.flush()
        try:
            return subprocess.call(
                cmd,
                stdout=log,
                stderr=log,
                stdin=subprocess.DEVNULL,
            )
        except KeyboardInterrupt:
            log.write("Interrupted.\n")
            return 130


def main() -> None:
    hide_console()

    tool_path = None
    if len(sys.argv) > 2 and sys.argv[1] == "--tool":
        tool_path = sys.argv[2]

    tool = find_tool(tool_path)

    folder = Path(TARGET_FOLDER).expanduser()
    if not folder.exists():
        sys.exit(f"ERROR: folder not found: {folder}")
    if not folder.is_dir():
        sys.exit(f"ERROR: not a directory: {folder}")
    if not PASSWORD:
        sys.exit("ERROR: PASSWORD is empty in the script")

    rc = run(tool, folder, PASSWORD, DELETE_ORIGINAL)
    sys.exit(rc)


if __name__ == "__main__":
    main()