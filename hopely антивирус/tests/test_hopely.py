"""Тесты модулей Hopely.

Запуск: py -m pytest tests -q
Тесты не требуют сети: ИИ-клиент подменяется заглушкой, песочница
проверяется только на защитных ветках (без реального запуска).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hopely.ai import AiAnalyzer, ChatClient  # noqa: E402
from hopely.config import Settings  # noqa: E402
from hopely.dynamic.sandbox import Sandbox  # noqa: E402
from hopely.models import DynamicReport, PeReport, YaraMatch, YaraReport  # noqa: E402
from hopely.pipeline import Pipeline  # noqa: E402
from hopely.scoring import (  # noqa: E402
    score_dynamic,
    score_static,
    score_yara,
    verdict_from_score,
)
from hopely.static.pe_module import PeAnalyzer  # noqa: E402
from hopely.static.yara_module import YaraScanner  # noqa: E402

NOTEPAD = r"C:\Windows\System32\notepad.exe"
ROOT = Path(__file__).resolve().parent.parent


def test_entropy_bounds() -> None:
    assert PeAnalyzer.calculate_entropy(b"") == 0.0
    assert PeAnalyzer.calculate_entropy(b"\x00" * 100) == 0.0
    assert PeAnalyzer.calculate_entropy(bytes(range(256))) == 8.0


def test_score_static_marks_wx_sections() -> None:
    pe = PeReport(is_pe=True, writable_executable_sections=[".text"], entropy_max=6.0)
    score, reasons = score_static(pe)
    assert score >= 30
    assert any("записи и исполнения" in reason for reason in reasons)


def test_score_static_obfuscated() -> None:
    pe = PeReport(is_pe=True, entropy_max=7.9)
    score, reasons = score_static(pe)
    assert score >= 35
    assert any("OBFUSCATED" in reason for reason in reasons)


def test_score_yara_weights() -> None:
    report = YaraReport(matches=[
        YaraMatch(rule="A", severity="high", description="тест"),
        YaraMatch(rule="B", severity="low", description="тест"),
    ])
    score, reasons = score_yara(report)
    assert score == 52
    assert len(reasons) == 2
    assert all(not reason.endswith(":") for reason in reasons)


def test_verdict_thresholds() -> None:
    assert verdict_from_score(0) == "CLEAN"
    assert verdict_from_score(30) == "SUSPICIOUS"
    assert verdict_from_score(90) == "MALWARE"


def test_dynamic_refused_without_permission() -> None:
    sandbox = Sandbox(allowed=False)
    report = sandbox.run(sys.executable)
    assert report.status == "refused"
    assert not report.ran
    score, reasons = score_dynamic(report)
    assert score == 0 and reasons


def test_dynamic_markers_scoring() -> None:
    report = DynamicReport(
        status="ran",
        network_connections=[{"remote": "1.1.1.1:443"}],
        child_processes=[{"name": "a"}, {"name": "b"}, {"name": "c"}],
        max_threads=20,
        io_write_bytes=64 * 1024 * 1024,
    )
    score, reasons = score_dynamic(report)
    assert score >= 60
    assert len(reasons) == 4


def test_yara_compiles_local_rules() -> None:
    scanner = YaraScanner(ROOT / "rules")
    assert scanner.backend_name in {"yara-x", "yara-python"}
    assert scanner._compiled is not None  # noqa: SLF001
    matches = scanner.scan_bytes(b"UPX0" + b"\x00" * 10 + b"UPX1" + b"UPX!")
    assert any(match.rule == "UPX_Packed" for match in matches)


def test_ai_analyzer_parses_json() -> None:
    class FakeClient(ChatClient):
        def __init__(self) -> None:  # noqa: D401
            super().__init__(api_key="test", model="fake")

        def generate(self, prompt: str, system_prompt: str = "") -> str:
            return '```json\n{"verdict": "suspicious", "confidence": 1.4, ' \
                   '"true": 1, "threat_family": "Packed", "explanation": "высокая энтропия", ' \
                   '"key_signals": ["entropy"], "false_positive_risk": "medium", ' \
                   '"yara_rules": []}\n```'.replace('"true": 1, ', "")

    analyzer = AiAnalyzer(FakeClient())
    verdict = analyzer.analyze({"heuristic_score": 30})
    assert verdict.status == "ok"
    assert verdict.verdict == "SUSPICIOUS"
    assert verdict.confidence == 1.0


def test_ai_skipped_without_key() -> None:
    analyzer = AiAnalyzer(ChatClient(api_key=None, model="fake"))
    verdict = analyzer.analyze({})
    assert verdict.status == "skipped"
    assert "HOPELY_AI_KEY" in (verdict.error or "")


def test_pipeline_clean_notepad() -> None:
    if not os.path.exists(NOTEPAD):
        return
    settings = Settings()
    settings.use_ai = False
    report = Pipeline(settings).scan_file(NOTEPAD)
    assert report.is_pe
    assert report.verdict == "CLEAN"
    assert report.modules["pe"].architecture in {"x64", "x86"}
    assert report.modules["yara"].backend != "none"


def test_pipeline_missing_file() -> None:
    report = Pipeline(Settings()).scan_file(r"C:\definitely\missing\file.exe")
    assert report.verdict == "ERROR"
    assert report.error == "Файл не найден"