"""Оркестратор: соединяет модули в единый проход анализа.

Порядок как в проекте:
    1. экспресс-анализ (pefile: заголовки, секция кода, IAT, энтропия);
    2. YARA-правила по байтам файла;
    3. песочница — только если статика дала OBFUSCATED и это разрешено;
    4. ИИ-модуль по собранному отчёту;
    5. итоговый вердикт по жёстким фильтрам с поправкой на ИИ.
"""

from __future__ import annotations

import os

from .ai import AiAnalyzer, ChatClient
from .config import Settings
from .dynamic import Sandbox
from .models import DynamicReport, PeReport, ScanReport, YaraReport
from .scoring import (
    combine,
    risk_rank,
    score_dynamic,
    score_static,
    score_yara,
    verdict_from_score,
)
from .static import PeAnalyzer, YaraScanner

EXIT_CODES = {"CLEAN": 0, "SUSPICIOUS": 1, "MALWARE": 2, "ERROR": 3}
PE_EXTENSIONS = (".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".com")


class Pipeline:
    """Пайплайн сканирования для набора настроек."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or Settings.from_env()
        self.pe = PeAnalyzer(disassembly=self.settings.disassembly)
        self.yara = YaraScanner(self.settings.rules_dir, enabled=self.settings.use_yara)
        client = ChatClient.from_config(self.settings.ai)
        self.ai = AiAnalyzer(client, enabled=self.settings.use_ai)

    # --------------------------------------------------------------- сканирование
    def scan_file(self, file_path: str) -> ScanReport:
        report = ScanReport(
            file_name=os.path.basename(file_path),
            file_path=os.path.abspath(file_path),
        )

        if not os.path.exists(file_path):
            report.verdict = "ERROR"
            report.error = "Файл не найден"
            return report
        if not os.path.isfile(file_path):
            report.verdict = "ERROR"
            report.error = "Это не файл, а каталог"
            return report

        try:
            pe_report = self.pe.analyze(file_path)
        except Exception as exc:  # noqa: BLE001 - отчёт должен вернуться всегда
            report.verdict = "ERROR"
            report.error = f"Статический анализ не удался: {exc}"
            return report
        if pe_report.error and not pe_report.is_pe and not pe_report.entropy_max:
            report.verdict = "ERROR"
            report.error = pe_report.error
            return report

        report.file_size_kb = pe_report.file_size_kb
        report.architecture = pe_report.architecture
        report.is_pe = pe_report.is_pe
        report.sha256 = pe_report.sha256
        report.entropy_max = pe_report.entropy_max
        report.obfuscated = pe_report.obfuscated

        static_score, reasons = score_static(pe_report)

        # Модуль YARA
        yara_report = self.yara.scan_file(file_path)
        yara_score, yara_reasons = score_yara(yara_report)
        reasons.extend(yara_reasons)
        if yara_report.error and self.settings.use_yara:
            reasons.append(f"YARA: {yara_report.error}")

        # Песочница: запускаем только для PE-файла, помеченного как OBFUSCATED
        dynamic_report = DynamicReport(status="skipped", reason="Не требуется")
        if self.settings.sandbox.enabled:
            dynamic_report = self._run_sandbox(file_path, pe_report)
        dynamic_score, dynamic_reasons = score_dynamic(dynamic_report)
        reasons.extend(dynamic_reasons)

        score = combine(static_score, yara_score, dynamic_score)
        local_verdict = verdict_from_score(score)

        # ИИ-модуль и проверка его правил
        payload = AiAnalyzer.build_payload(
            pe_report, yara_report, dynamic_report, score, report.file_name
        )
        ai_verdict = self.ai.analyze(payload)
        ai_match_score, ai_matches = self._verify_ai_rules(
            ai_verdict.yara_rules, file_path
        )
        if ai_matches:
            yara_report.matches.extend(ai_matches)
            score += ai_match_score
            reasons.append(
                "Правила, предложенные ИИ, совпали: "
                + ", ".join(match.rule for match in ai_matches)
            )

        report.score = score
        report.reasons = reasons
        report.verdict = self._final_verdict(local_verdict, ai_verdict.verdict, score)
        if ai_verdict.status != "ok" and ai_verdict.error:
            report.reasons.append(f"ИИ: {ai_verdict.error}")
        report.modules = {
            "pe": pe_report,
            "yara": yara_report,
            "dynamic": dynamic_report,
            "ai": ai_verdict,
        }
        return report

    def scan_folder(self, folder_path: str, extensions: tuple = PE_EXTENSIONS) -> list:
        """Рекурсивно сканировать каталог."""
        results = []
        for root, _dirs, files in os.walk(folder_path):
            for name in files:
                if name.lower().endswith(extensions):
                    results.append(self.scan_file(os.path.join(root, name)))
        return results

    # ------------------------------------------------------------- внутренности
    def _run_sandbox(self, file_path: str, pe_report: PeReport) -> DynamicReport:
        """Запустить файл в песочнице, если выполнены все условия."""
        if not pe_report.is_pe:
            return DynamicReport(status="skipped", reason="Файл не PE — запуск не нужен")
        sandbox = Sandbox(
            allowed=self.settings.sandbox.permitted,
            watch_seconds=self.settings.sandbox.watch_seconds,
            memory_limit_mb=self.settings.sandbox.memory_limit_mb,
            allow_unsigned=self.settings.sandbox.allow_unsigned,
        )
        report = sandbox.run(file_path)
        if report.ran:
            report.markers = list(report.markers)
            if pe_report.obfuscated:
                report.markers.append("static: OBFUSCATED (высокая энтропия)")
        return report

    def _verify_ai_rules(self, rules: list, file_path: str) -> tuple[int, list]:
        """Скомпилировать правила от ИИ и прогнать по файлу."""
        if not rules:
            return 0, []
        try:
            with open(file_path, "rb") as handle:
                data = handle.read(YaraScanner.MAX_FILE_BYTES)
        except OSError:
            return 0, []
        matches: list = []
        for rule_text in rules:
            try:
                found = self.yara.scan_rules_text(rule_text, data)
            except Exception:  # noqa: BLE001 - правило от ИИ может быть битым
                continue
            matches.extend(found)
        if not matches:
            return 0, []
        return score_yara(YaraReport(matches=matches))[0], matches

    @staticmethod
    def _final_verdict(local: str, ai: str, score: int) -> str:
        """Итог: ИИ уточняет вердикт, но не отменяет жёсткие фильтры."""
        if score >= 60 or local == "MALWARE":
            return "MALWARE"
        if ai == "MALWARE" and score >= 25:
            return "MALWARE"
        if ai == "SUSPICIOUS" or local == "SUSPICIOUS":
            return "SUSPICIOUS"
        if ai == "CLEAN":
            return "CLEAN"
        return verdict_from_score(score)


def worst_verdict(verdicts) -> str:
    """Самый опасный вердикт из списка (для кодов возврата CLI)."""
    return max(verdicts, key=risk_rank, default="CLEAN")