from __future__ import annotations

"""Compatibility entrypoint for the WorkSpace Security Local Console.

The implementation moved to ``security_local_console_v2`` so the user-facing command
and existing imports remain stable while the console grows into a testable analyst UI.
"""

from .security_local_console_v2 import build_server, main, validate_loopback_host

__all__ = ["build_server", "main", "validate_loopback_host"]


if __name__ == "__main__":
    raise SystemExit(main())
