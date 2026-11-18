"""Модуль YARA-правил.

Компилирует текстовые правила из каталога `rules/` и прогоняет через них
байты проверяемого файла. Поддерживаются два бэкенда:

    py   — классический yara-python (если установлен);
    rust — yara-x, порт на Rust (используется, если yara-python недоступен).

Если ни одного бэкенда нет, модуль честно сообщает об этом в отчёте,
и остальные этапы анализа продолжают работать.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..models import YaraMatch, YaraReport

try:
    import yara  # yara-python
except Exception:  # noqa: BLE001
    yara = None

try:
    import yara_x
except Exception:  # noqa: BLE001
    yara_x = None


class YaraBackendError(RuntimeError):
    """Правила не скомпилировались."""


class YaraScanner:
    """Прогон файла по YARA-правилам (локальным и сгенерированным ИИ)."""

    MAX_FILE_BYTES = 128 * 1024 * 1024  # 128 МБ — дальше не читаем в память

    def __init__(self, rules_dir: str | os.PathLike | None = None,
                 backend: str = "auto", enabled: bool = True):
        self.rules_dir = Path(rules_dir) if rules_dir else None
        self.enabled = enabled
        self.backend_name = "none"
        self._sources = self._read_sources() if enabled else {}
        self._compiled = None
        self._compile()

    # ------------------------------------------------------------------ загрузка
    def _read_sources(self) -> dict:
        """Прочитать все .yar/.yara файлы каталога правил."""
        sources: dict = {}
        if not self.rules_dir or not self.rules_dir.is_dir():
            return sources
        for path in sorted(self.rules_dir.iterdir()):
            if path.suffix.lower() not in {".yar", ".yara"}:
                continue
            try:
                sources[path.stem] = path.read_text(encoding="utf-8")
            except OSError:
                continue
        return sources

    def _compile(self) -> None:
        if not self.enabled or not self._sources:
            return
        if yara is not None:
            try:
                self._compiled = yara.compile(sources=self._sources)
                self.backend_name = "yara-python"
                return
            except Exception:  # noqa: BLE001
                self._compiled = None
        if yara_x is not None:
            try:
                compiler = yara_x.Compiler()
                for source in self._sources.values():
                    compiler.add_source(source)
                self._compiled = compiler.build()
                self.backend_name = "yara-x"
            except Exception:  # noqa: BLE001
                self._compiled = None

    # --------------------------------------------------------------- сканирование
    def scan_bytes(self, data: bytes, source: str = "local") -> list:
        """Прогнать произвольные байты через правила, вернуть список YaraMatch."""
        if self._compiled is None:
            return []
        matches: list = []
        if self.backend_name == "yara-python":
            for match in self._compiled.match(data=data):
                meta = getattr(match, "meta", {}) or {}
                matches.append(
                    YaraMatch(
                        rule=match.rule,
                        severity=str(meta.get("severity", "medium")).lower(),
                        description=str(meta.get("description", "")),
                        tags=list(getattr(match, "tags", []) or []),
                        source=source,
                    )
                )
            return matches

        results = self._compiled.scan(data)
        for rule in results.matching_rules:
            meta = self._metadata(rule)
            matches.append(
                YaraMatch(
                    rule=rule.identifier,
                    severity=self._stringify(meta.get("severity", "medium")).lower(),
                    description=self._stringify(meta.get("description", "")),
                    tags=[str(tag) for tag in (getattr(rule, "tags", []) or [])],
                    source=source,
                )
            )
        return matches

    @staticmethod
    def _metadata(rule) -> dict:
        """Привести метаданные правила к словарю.

        yara-x отдаёт `metadata` списком пар (ключ, MetaType).
        """
        raw = getattr(rule, "metadata", {}) or {}
        if isinstance(raw, dict):
            return raw
        result = {}
        try:
            for key, value in raw:
                result[key] = value
        except (TypeError, ValueError):
            return {}
        return result

    @staticmethod
    def _stringify(value: object) -> str:
        """yara-x отдаёт метаданные объектами MetaType — приводим к строке."""
        if isinstance(value, (str, bytes)):
            return value.decode() if isinstance(value, bytes) else value
        inner = getattr(value, "value", None)
        if isinstance(inner, (str, bytes)):
            return inner.decode() if isinstance(inner, bytes) else inner
        return str(value)

    def scan_file(self, file_path: str) -> YaraReport:
        report = YaraReport(
            backend=self.backend_name,
            rules_loaded=len(self._sources),
            rules_compiled=len(self._sources) if self._compiled is not None else 0,
        )
        if not self.enabled:
            report.error = "Модуль YARA отключён"
            return report
        if self._compiled is None:
            report.error = (
                "Нет доступного YARA-бэкенда: установите yara-python или yara-x "
                "(pip install -r requirements.txt)"
            )
            return report
        try:
            size = os.path.getsize(file_path)
            with open(file_path, "rb") as handle:
                data = handle.read(min(size, self.MAX_FILE_BYTES))
            report.matches = self.scan_bytes(data, source="local")
        except OSError as exc:
            report.error = f"Не удалось прочитать файл: {exc}"
        except Exception as exc:  # noqa: BLE001
            report.error = f"Ошибка YARA-сканирования: {exc}"
        return report

    def scan_rules_text(self, rules_text: str, data: bytes) -> list:
        """Скомпилировать временные правила (например, от ИИ) и прогнать байты."""
        if yara is not None:
            handle = yara.compile(source=rules_text)
            matches = []
            for match in handle.match(data=data):
                meta = getattr(match, "meta", {}) or {}
                matches.append(
                    YaraMatch(
                        rule=match.rule,
                        severity=str(meta.get("severity", "medium")).lower(),
                        description=str(meta.get("description", "")),
                        tags=list(getattr(match, "tags", []) or []),
                        source="ai",
                    )
                )
            return matches
        if yara_x is not None:
            compiler = yara_x.Compiler()
            compiler.add_source(rules_text)
            results = compiler.build().scan(data)
            matches = []
            for rule in results.matching_rules:
                meta = self._metadata(rule)
                matches.append(
                    YaraMatch(
                        rule=rule.identifier,
                        severity=self._stringify(meta.get("severity", "medium")).lower(),
                        description=self._stringify(meta.get("description", "")),
                        tags=[str(tag) for tag in (getattr(rule, "tags", []) or [])],
                        source="ai",
                    )
                )
            return matches
        return []