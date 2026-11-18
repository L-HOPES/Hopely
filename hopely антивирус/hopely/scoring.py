"""Жёсткие логические фильтры: перевод данных модулей в балл риска.

Здесь нет «магии» ИИ — только детерминированные правила из проекта:
энтропия, права секций, импорты WinAPI, совпадения YARA и поведение
в песочнице. Балл риска используется как страховка независимо от
вердикта ИИ, чтобы вредоносный файл не проскочил из-за сбоя сети.
"""

from __future__ import annotations

from .config import (
    ENTROPY_CRITICAL,
    ENTROPY_SUSPICIOUS,
    SCORE_MALWARE,
    SCORE_SUSPICIOUS,
)
from .models import DynamicReport, PeReport, YaraReport
from .static.pe_module import PeAnalyzer

SEVERITY_WEIGHT = {"low": 12, "medium": 24, "high": 40}


def score_static(pe: PeReport) -> tuple[int, list]:
    """Балл и причины по результатам PE-разбора."""
    score = 0
    reasons: list = []

    if pe.error:
        return 0, reasons

    score += PeAnalyzer.import_score(pe.suspicious_imports)
    if pe.suspicious_imports:
        reasons.append(
            "Подозрительные импорты WinAPI: "
            + ", ".join(sorted(pe.suspicious_imports)[:12])
        )

    if pe.entropy_max >= ENTROPY_CRITICAL:
        score += 35
        reasons.append(
            f"Критическая энтропия {pe.entropy_max} — файл, вероятно, "
            "упакован или зашифрован (OBFUSCATED)"
        )
    elif pe.entropy_max >= ENTROPY_SUSPICIOUS:
        score += 15
        reasons.append(f"Повышенная энтропия {pe.entropy_max} — возможен упаковщик")

    if pe.writable_executable_sections:
        score += 30
        reasons.append(
            "Секции с правами записи и исполнения: "
            + ", ".join(pe.writable_executable_sections)
            + " (самомодифицирующийся код или распаковка в памяти)"
        )

    if not pe.is_pe:
        reasons.append("Файл не является PE-образом: проверена только общая энтропия")

    return score, reasons


def score_yara(yara_report: YaraReport) -> tuple[int, list]:
    """Балл и причины по совпадениям YARA."""
    score = 0
    reasons: list = []
    for match in yara_report.matches:
        score += SEVERITY_WEIGHT.get(getattr(match, "severity", "medium"), 24)
        label = "правило ИИ" if getattr(match, "source", "local") == "ai" else "правило"
        description = getattr(match, "description", "") or ""
        reason = f"YARA ({label}) {match.rule}: {description}".strip().rstrip(":")
        reasons.append(reason)
    return score, reasons


def score_dynamic(dynamic: DynamicReport) -> tuple[int, list]:
    """Балл и причины по поведению в песочнице."""
    score = 0
    reasons: list = []

    if dynamic.status == "refused":
        reasons.append(f"Песочница отказалась запускать файл: {dynamic.reason}")
        return 0, reasons
    if not dynamic.ran:
        return 0, reasons

    net_count = len(dynamic.network_connections)
    if net_count:
        score += min(30, 15 * net_count)
        reasons.append(f"Сетевые соединения из песочницы: {net_count}")

    if len(dynamic.child_processes) > 2:
        score += 20
        reasons.append(
            f"Порождено дочерних процессов: {len(dynamic.child_processes)} "
            "(индикатор инъекций и закрепления)"
        )

    if dynamic.max_threads >= 16:
        score += 15
        reasons.append(
            f"Аномальная многопоточность: {dynamic.max_threads} потоков"
        )

    writes_mb = dynamic.io_write_bytes / (1024 * 1024)
    if writes_mb >= 20:
        score += 20
        reasons.append(
            f"Интенсивная запись на диск: {writes_mb:.1f} МБ за сеанс "
            "(индикатор шифровальщика или вайпера)"
        )

    score += dynamic.score
    return score, reasons


def combine(static_score: int, yara_score: int, dynamic_score: int) -> int:
    """Общий балл риска (сумма модулей)."""
    return static_score + yara_score + dynamic_score


def verdict_from_score(score: int) -> str:
    if score >= SCORE_MALWARE:
        return "MALWARE"
    if score >= SCORE_SUSPICIOUS:
        return "SUSPICIOUS"
    return "CLEAN"


def risk_rank(verdict: str) -> int:
    """Числовой вес вердикта для выбора худшего результата."""
    return {"CLEAN": 0, "UNKNOWN": 1, "SUSPICIOUS": 2, "MALWARE": 3, "ERROR": 4}.get(verdict, 1)