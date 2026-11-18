"""Статический (экспресс) анализ файла без его запуска."""

from __future__ import annotations

from .pe_module import PeAnalyzer
from .yara_module import YaraScanner

__all__ = ["PeAnalyzer", "YaraScanner"]