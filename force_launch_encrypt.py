#!/usr/bin/env python3
"""
One-shot launcher for encrypt_folder.py.

The folder and password are hardcoded below — running this script
immediately encrypts the folder with no prompts.

Place this script in the SAME directory as encrypt_folder.py, or pass
--tool /path/to/encrypt_folder.py when running it.
"""

import subprocess
import sys
from pathlib import Path

# ===========================================================================
#  HARDCODED SETTINGS — edit these two lines
# ===========================================================================
TARGET_FOLDER = r"/path/to/your/folder"     # e.g. r"C:\Users\me\Documents\secret"
PASSWORD      = "YourPasswordHere"          # e.g. "MyStr0ngPass!"
DELETE_ORIGINAL = False                     # set True to delete source files after encryption
# ===========================================================================

TOOL_NAME = "encrypt_folder.py"


# ---------------------------------------------------------------------------
# Locate the underlying tool
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
def run(tool: Path, folder: Path, password: str, delete: bool) -> int:
    cmd = [sys.executable, str(tool), str(folder), password]
    if delete:
        cmd.append("--delete")

    display = " ".join("********" if part == password else part for part in cmd)
    print(f"Running: {display}\n")

    try:
        return subprocess.call(cmd)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    # Allow --tool override, but no other interaction.
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

    print(f"=== Folder Encryption ({TOOL_NAME}) ===")
    print(f"  folder : {folder}")
    print(f"  delete : {DELETE_ORIGINAL}")

    rc = run(tool, folder, PASSWORD, DELETE_ORIGINAL)
    if rc == 0:
        print("\n✔ Done.")
    else:
        print(f"\n✘ {TOOL_NAME} exited with code {rc}.")
    sys.exit(rc)


if __name__ == "__main__":
    main()