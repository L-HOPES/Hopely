"""ИИ-модуль: собирает отчёт для модели, разбирает вердикт, проверяет правила.

ИИ получает только обезличенные факты (имена секций, импорты, совпадения,
поведенческие метрики). Сгенерированные моделью YARA-правила сразу
компилируются локально и прогоняются по файлу — если правило ломается,
оно отбраковывается и не попадает в отчёт.
"""

from __future__ import annotations

import json
import re

from ..models import AiVerdict, DynamicReport, PeReport, YaraReport
from .client import AiClientError, ChatClient

VALID_VERDICTS = {"CLEAN", "SUSPICIOUS", "MALWARE"}


class AiAnalyzer:
    """Обёртка над моделью: промпт, разбор JSON и проверка YARA от ИИ."""

    def __init__(self, client: ChatClient, enabled: bool = True):
        self.client = client
        self.enabled = enabled

    # --------------------------------------------------------------- построение
    @staticmethod
    def build_payload(pe: PeReport, yara_report: YaraReport,
                      dynamic: DynamicReport, score: int,
                      file_name: str = "") -> dict:
        """Компактный контекст для модели: только значимые факты."""
        return {
            "file": {
                "name": file_name,
                "architecture": pe.architecture,
                "size_kb": pe.file_size_kb,
                "sha256": pe.sha256,
                "compile_time": pe.compile_timestamp,
                "is_pe": pe.is_pe,
            },
            "entropy": {
                "max": pe.entropy_max,
                "sections": pe.entropy_sections,
                "obfuscated": pe.obfuscated,
            },
            "sections": {
                "writable_executable": pe.writable_executable_sections,
            },
            "imports": {
                "suspicious": pe.suspicious_imports,
                "dlls": pe.imported_dlls[:20],
            },
            "yara_matches": [
                {
                    "rule": match.rule,
                    "severity": match.severity,
                    "description": match.description,
                    "source": match.source,
                }
                for match in yara_report.matches
            ],
            "dynamic": {
                "status": dynamic.status,
                "reason": dynamic.reason,
                "network_connections": dynamic.network_connections[:10],
                "child_processes": dynamic.child_processes[:10],
                "max_threads": dynamic.max_threads,
                "io_write_bytes": dynamic.io_write_bytes,
                "markers": dynamic.markers,
            },
            "heuristic_score": score,
            "disassembly_sample": pe.disassembly_sample[:20],
        }

    # ------------------------------------------------------------------ вызов
    def analyze(self, payload: dict) -> AiVerdict:
        verdict = AiVerdict(model=self.client.model)
        if not self.enabled:
            verdict.status = "skipped"
            verdict.error = "ИИ-модуль отключён"
            return verdict
        if not self.client.configured:
            verdict.status = "skipped"
            verdict.error = (
                "Ключ ИИ не найден: добавьте HOPELY_AI_KEY в .env. "
                "Итог выставлен по локальным правилам."
            )
            return verdict

        prompt = (
            "Отчёт антивируса Hopely:\n"
            + json.dumps(payload, ensure_ascii=False, indent=2)
            + "\n\nДай вердикт строго по JSON-схеме."
        )
        try:
            raw = self.client.generate(prompt)
        except AiClientError as exc:
            verdict.status = "error"
            verdict.error = str(exc)
            return verdict

        data = self._parse_json(raw)
        if data is None:
            verdict.status = "error"
            verdict.error = "Не удалось разобрать JSON-ответ модели"
            return verdict

        verdict.status = "ok"
        verdict.verdict = self._normalize_verdict(data.get("verdict"))
        verdict.confidence = self._clamp(data.get("confidence"))
        verdict.threat_family = str(data.get("threat_family") or "")[:120]
        verdict.explanation = str(data.get("explanation") or "")[:2000]
        verdict.false_positive_risk = str(data.get("false_positive_risk") or "")[:20]
        verdict.key_signals = [str(item)[:200] for item in (data.get("key_signals") or [])][:8]
        rules = data.get("yara_rules") or []
        verdict.yara_rules = [str(rule) for rule in rules if str(rule).strip()][:3]
        return verdict

    # ------------------------------------------------------------- разбор ответа
    @staticmethod
    def _parse_json(raw: str) -> dict | None:
        """Разобрать ответ, сняв возможные ```json-обёртки."""
        text = raw.strip()
        fenced = re.search(r"```(?:json)?\s*(.+?)```", text, re.DOTALL)
        if fenced:
            text = fenced.group(1).strip()
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return None
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _normalize_verdict(value: object) -> str:
        text = str(value or "").strip().upper()
        return text if text in VALID_VERDICTS else "UNKNOWN"

    @staticmethod
    def _clamp(value: object) -> float:
        try:
            number = float(value)
        except (TypeError, ValueError):
            return 0.0
        return round(max(0.0, min(1.0, number)), 2)