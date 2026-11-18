"""Совместимость со старым API движка.

Раньше здесь был монолитный модуль. Теперь логика разнесена по модулям
пакета `hopely` (static / dynamic / ai / scoring), а этот файл оставлен
как фасад: старый код с `HopelyAntivirus().scan_file(...)` продолжит
работать и получит те же поля отчёта.
"""

from __future__ import annotations

import os
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from hopely.config import ENTROPY_CRITICAL, ENTROPY_SUSPICIOUS  # noqa: E402
from hopely.pipeline import Pipeline  # noqa: E402
from hopely.static.pe_module import SUSPICIOUS_API  # noqa: E402


class HopelyAntivirus:
    """Фасад над пайплайном Hopely (совместимый со старым интерфейсом)."""

    def __init__(self, entropy_suspicious: float = ENTROPY_SUSPICIOUS,
                 entropy_critical: float = ENTROPY_CRITICAL,
                 use_ai: bool = True, use_yara: bool = True):
        self.entropy_suspicious = entropy_suspicious
        self.entropy_critical = entropy_critical
        self._pipeline = Pipeline()
        self._pipeline.settings.use_ai = use_ai
        self._pipeline.settings.use_yara = use_yara
        self._pipeline.yara.enabled = use_yara

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        from hopely.static.pe_module import PeAnalyzer

        return PeAnalyzer.calculate_entropy(data)

    def scan_file(self, file_path: str):
        """Сканировать файл и вернуть отчёт с методом `to_dict()`."""
        return self._pipeline.scan_file(file_path)

    def scan_folder(self, folder_path: str):
        return self._pipeline.scan_folder(folder_path)

SUSPICIOUS_WINAPI = SUSPICIOUS_API

__all__ = ["HopelyAntivirus", "SUSPICIOUS_API", "SUSPICIOUS_WINAPI"]