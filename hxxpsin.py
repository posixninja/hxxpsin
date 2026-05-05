#!/usr/bin/env python3
"""
hxxpsin — convenience launcher.

Adds the src/ directory to sys.path so you don't have to, and picks a sensible
default --out directory (./output/<hostname>-<timestamp>) when one isn't given.

Usage:
    ./hxxpsin.py http://target.com                  # implicit "scan"
    ./hxxpsin.py http://target.com --active-scan    # any flags pass through
    ./hxxpsin.py quick http://target.com            # explicit subcommand
    ./hxxpsin.py scan http://target.com --out ./mydir  # explicit --out wins
    ./hxxpsin.py --help

Subcommands (forwarded to src/main.py): scan | quick | repeat | fuzz
"""

import os
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent

# Re-exec under the project's venv if we're not already running under it.
# Avoids "h2 package not installed" / dependency drift when the user invokes
# the script via the system python.
_VENV_PY = ROOT / ".venv" / "bin" / "python"
if _VENV_PY.exists() and Path(sys.executable).resolve() != _VENV_PY.resolve():
    os.execv(str(_VENV_PY), [str(_VENV_PY), str(Path(__file__).resolve())] + sys.argv[1:])

sys.path.insert(0, str(ROOT / "src"))

_SUBCOMMANDS = {"scan", "quick", "repeat", "fuzz"}


def _augment_argv(argv: list[str]) -> list[str]:
    """Inject `scan` if the first arg looks like a URL, and pick a default
    --out under ./output/ when one isn't provided."""
    out = list(argv)

    # If the first non-flag arg is a URL, default the subcommand to "scan"
    if out and out[0] not in _SUBCOMMANDS and not out[0].startswith("-"):
        out.insert(0, "scan")

    # Default --out for scan/quick if user didn't specify one
    if out and out[0] in ("scan", "quick") and "--out" not in out:
        target = next((a for a in out if a.startswith(("http://", "https://"))), None)
        if target:
            host = (urlparse(target).hostname or "target").replace(":", "_")
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            out += ["--out", str(ROOT / "output" / f"{host}-{ts}")]

    return out


def main() -> None:
    args = sys.argv[1:]
    if "--tui" in args:
        args.remove("--tui")
        from tui import HxxpsinApp
        load_dir = None
        if "--load" in args:
            idx = args.index("--load")
            load_dir = args[idx + 1]
            args = args[:idx] + args[idx + 2:]
        HxxpsinApp(load_dir=load_dir).run()
        return

    sys.argv = ["hxxpsin"] + _augment_argv(args)
    from main import main as _main
    _main()


if __name__ == "__main__":
    main()
