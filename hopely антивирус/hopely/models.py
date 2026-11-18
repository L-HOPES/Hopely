"""Структуры данных Hopely.

Каждый модуль (static / dynamic / ai) заполняет свою часть отчёта,
`ScanReport` собирает их вместе. Все объекты сериализуются в JSON
через `to_dict()`, чтобы CLI и лаунчер работали с одинаковым форматом.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


def _as_dict(obj: object) -> object:
    if hasattr(obj, "to_dict"):
        return obj.to_dict()  # type: ignore[no-any-return]
    if isinstance(obj, list):
        return [_as_dict(item) for item in obj]
    return obj


@dataclass
class PeReport:
    """Результат разбора PE-структуры файла (модуль static/pe_module)."""

    is_pe: bool = False
    architecture: str = "unknown"
    file_size_kb: float = 0.0
    sha256: str = ""
    md5: str = ""
    entry_point: str = ""
    compile_timestamp: str | None = None
    entropy_max: float = 0.0
    entropy_sections: dict = field(default_factory=dict)
    writable_executable_sections: list = field(default_factory=list)
    suspicious_imports: list = field(default_factory=list)
    imported_dlls: list = field(default_factory=list)
    obfuscated: bool = False
    disassembly_sample: list = field(default_factory=list)
    error: str | None = None

    @property
    def has_write_execute_section(self) -> bool:
        return bool(self.writable_executable_sections)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["has_write_execute_section"] = self.has_write_execute_section
        return data


@dataclass
class YaraMatch:
    """Одно совпадение с YARA-правилом."""

    rule: str
    severity: str = "medium"
    description: str = ""
    tags: list = field(default_factory=list)
    source: str = "local"  # local | ai (правило придумано ИИ)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class YaraReport:
    """Итог прогона файла через YARA-правила (модуль static/yara_module)."""

    backend: str = "none"
    rules_loaded: int = 0
    rules_compiled: int = 0
    matches: list = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["matches"] = [_as_dict(item) for item in self.matches]
        return data


@dataclass
class DynamicReport:
    """Результат песочницы (модуль dynamic/sandbox)."""

    status: str = "skipped"  # skipped | ran | refused | error
    reason: str = ""
    duration_seconds: float = 0.0
    exit_code: int | None = None
    signature: str = "unknown"  # valid | unsigned | invalid | unknown
    io_read_bytes: int = 0
    io_write_bytes: int = 0
    max_threads: int = 0
    child_processes: list = field(default_factory=list)
    network_connections: list = field(default_factory=list)
    score: int = 0
    markers: list = field(default_factory=list)
    error: str | None = None

    @property
    def ran(self) -> bool:
        return self.status == "ran"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AiVerdict:
    """Вердикт ИИ-модуля по собранному отчёту."""

    status: str = "skipped"  # ok | skipped | error
    model: str = ""
    verdict: str = "UNKNOWN"  # CLEAN | SUSPICIOUS | MALWARE | UNKNOWN
    confidence: float = 0.0
    threat_family: str = ""
    explanation: str = ""
    key_signals: list = field(default_factory=list)
    false_positive_risk: str = ""
    yara_rules: list = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanReport:
    """Полный отчёт сканирования одного файла."""

    file_name: str = ""
    file_path: str = ""
    file_size_kb: float = 0.0
    architecture: str = "unknown"
    is_pe: bool = False
    sha256: str = ""
    # Плоские поля, которые показывает лаунчер
    entropy_max: float = 0.0
    score: int = 0
    verdict: str = "UNKNOWN"  # CLEAN | SUSPICIOUS | MALWARE | ERROR
    obfuscated: bool = False
    reasons: list = field(default_factory=list)
    modules: dict = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["modules"] = {name: _as_dict(value) for name, value in self.modules.items()}
        return data