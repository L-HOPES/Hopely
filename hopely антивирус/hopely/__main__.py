"""Точка входа: py -m hopely --target <путь>."""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())