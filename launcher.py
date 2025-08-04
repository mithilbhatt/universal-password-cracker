#!/usr/bin/env python3
"""
Universal Password Cracker – Auto-Installer Launcher
Copyright (c) 2024-2025  <your-name>

• Detects missing dependencies and installs them.
• Works on standard Python, Kali Linux (PEP-668), and virtual-envs.
• After installation, launches the GUI application.
"""

from __future__ import annotations

import importlib
import os
import platform
import subprocess
import sys
import traceback
from pathlib import Path

# --------------------------------------------------------------------------- #
# 1.  EDIT HERE if you add/remove runtime dependencies
# --------------------------------------------------------------------------- #
REQUIRED_PACKAGES: list[str] = [
    "py7zr",
    "pycryptodome",
    "PyPDF2",
    "rarfile",
    "msoffcrypto-tool",
    "chardet",
    "reportlab",
]

# --------------------------------------------------------------------------- #
# 2.  Helper functions
# --------------------------------------------------------------------------- #
def _run_pip(args: list[str]) -> subprocess.CompletedProcess:
    """Run pip and return the CompletedProcess (stdout/stderr captured)."""
    cmd = [sys.executable, "-m", "pip"] + args
    return subprocess.run(
        cmd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _install_package(pkg: str) -> bool:
    """Install a single package, retrying with --break-system-packages if needed."""
    print(f"📦  Installing {pkg} …", flush=True)

    # First attempt: normal install
    result = _run_pip(["install", "--quiet", pkg])
    if result.returncode == 0:
        print(f"✅  {pkg} installed")
        return True

    # Detect PEP-668 / externally-managed error
    if "externally-managed-environment" in result.stderr:
        print("⚠️  Externally-managed environment detected – retrying with --break-system-packages")
        result2 = _run_pip(["install", "--quiet", "--break-system-packages", pkg])
        if result2.returncode == 0:
            print(f"✅  {pkg} installed (using --break-system-packages)")
            return True
        result = result2  # fall through to error reporting

    # Any other failure
    print(f"❌  Failed to install {pkg}")
    if os.getenv("LAUNCHER_VERBOSE"):
        # Show the last few stderr lines for debugging
        print(result.stderr.strip().splitlines()[-5:])
    return False


def _ensure_dependencies() -> None:
    """Import each dependency; install if missing."""
    missing: list[str] = []
    for pkg in REQUIRED_PACKAGES:
        try:
            # msoffcrypto-tool is imported as msoffcrypto
            importlib.import_module("msoffcrypto" if pkg.startswith("msoffcrypto") else pkg)
            print(f"✅  {pkg} is already installed")
        except ImportError:
            missing.append(pkg)

    if not missing:
        print("🎉  All dependencies present – nothing to install")
        return

    print(f"📥  Installing {len(missing)} missing package(s)…\n")
    for pkg in missing:
        if not _install_package(pkg):
            print(
                "\n⚠️  Unable to install all dependencies automatically.\n"
                "    Please install them manually and re-run the launcher."
            )
            sys.exit(1)


def _launch_gui() -> None:
    """Locate and execute the GUI script."""
    candidates = ("crackgui.py", "universal_cracker.py")
    for script in candidates:
        path = Path(__file__).with_name(script)
        if path.exists():
            print(f"🚀  Launching GUI ⇒ {path.name}")
            # Execute the script in a fresh global namespace
            globals_dict = {"__name__": "__main__", "__file__": str(path)}
            exec(compile(path.read_text(encoding="utf-8"), str(path), "exec"), globals_dict)
            return
    print(f"❌  GUI script not found. Expected one of: {', '.join(candidates)}")
    sys.exit(1)


# --------------------------------------------------------------------------- #
# 3.  Main entry-point
# --------------------------------------------------------------------------- #
def main() -> None:
    print("🔐  Universal Password Cracker – Auto Installer")
    print("=" * 60)

    try:
        _ensure_dependencies()
        print("\n" + "=" * 60)
        _launch_gui()
    except KeyboardInterrupt:
        print("\n⏹️  Interrupted by user")
    except Exception as exc:  # pylint: disable=broad-except
        print(f"\n❌  Launcher error: {exc}")
        if os.getenv("LAUNCHER_VERBOSE"):
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

