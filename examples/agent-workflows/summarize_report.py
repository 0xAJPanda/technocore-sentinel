#!/usr/bin/env python3
"""Source-tree adapter for the production Sentinel report summarizer."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from technocore_sentinel.workflow import summarize_stdin  # noqa: E402

ERROR_MESSAGE = "error: invalid report\n"


def main() -> int:
    try:
        output = summarize_stdin(sys.stdin.buffer)
    except Exception:
        sys.stderr.write(ERROR_MESSAGE)
        return 1
    sys.stdout.write(output + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
