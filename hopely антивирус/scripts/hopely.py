"""Тонкая обёртка командной строки Hopely.

Вся логика живёт в пакете `hopely/` в корне проекта. Этот файл нужен,
чтобы старые команды и bat-файлы продолжали работать:

    py scripts\\hopely.py --target "C:\\path\\to\\file.exe"
"""

from __future__ import annotations

import os
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from hopely.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())