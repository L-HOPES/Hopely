"""Командная строка Hopely.

Примеры:
    py -m hopely --target "C:\\path\\to\\file.exe"
    py -m hopely --target "C:\\Downloads" --json report.json
    py -m hopely --target file.exe --dynamic --dynamic-untrusted

Коды возврата: 0 — CLEAN, 1 — SUSPICIOUS, 2 — MALWARE, 3 — ошибка.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .config import Settings
from .pipeline import EXIT_CODES, Pipeline, worst_verdict

VERDICT_LABELS = {
    "CLEAN": "[OK]    ЧИСТО",
    "SUSPICIOUS": "[WARN]  ПОДОЗРИТЕЛЬНО",
    "MALWARE": "[ALERT] ВРЕДОНОСНО",
    "ERROR": "[ERR]   ОШИБКА",
    "UNKNOWN": "[?]     НЕТ ДАННЫХ",
}


def _force_utf8_console() -> None:
    """Принудительно включить UTF-8, иначе кириллица ломается в cmd."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hopely",
        description="Hopely — антивирусный сканер: PE-анализ, YARA, песочница и ИИ",
    )
    parser.add_argument("-t", "--target", required=True, help="Путь к файлу или каталогу")
    parser.add_argument("-f", "--folder", action="store_true", help="Сканировать каталог рекурсивно")
    parser.add_argument("-j", "--json", dest="json_path", help="Сохранить отчёт в JSON-файл")
    parser.add_argument("-q", "--quiet", action="store_true", help="Только итоговый вердикт")
    parser.add_argument("--no-disasm", action="store_true", help="Не выводить дизассемблирование")
    parser.add_argument("--no-yara", action="store_true", help="Не использовать YARA-правила")
    parser.add_argument("--no-ai", action="store_true", help="Не обращаться к ИИ-модели")
    parser.add_argument(
        "--dynamic",
        action="store_true",
        help="Динамический анализ в песочнице (требует HOPELY_SANDBOX_ALLOW=1)",
    )
    parser.add_argument(
        "--dynamic-untrusted",
        action="store_true",
        help="Разрешить запуск файла с недействительной подписью в песочнице",
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Показывать технические предупреждения библиотек")
    return parser


def _setup_logging(verbose: bool) -> None:
    """Без -v скрываем технические предупреждения библиотек."""
    if verbose:
        return
    import warnings

    warnings.simplefilter("ignore")


def print_report(report: dict, disassembly: bool = True) -> None:
    """Вывести отчёт в человекочитаемом виде."""
    modules = report.get("modules") or {}
    pe = modules.get("pe") or {}
    yara = modules.get("yara") or {}
    dynamic = modules.get("dynamic") or {}
    ai = modules.get("ai") or {}

    print("=" * 62)
    print(f"Файл:         {report['file_name']}")
    print(f"Путь:         {report['file_path']}")
    print(f"Размер:       {report['file_size_kb']} КБ")
    print(f"Архитектура:  {report['architecture']}")
    print(f"SHA-256:      {report.get('sha256', '')[:32]}…")
    print(f"Энтропия:     {report['entropy_max']} / 8.0")
    print(f"Балл риска:   {report['score']}")
    if pe.get("suspicious_imports"):
        print(f"Импорты:      {', '.join(sorted(pe['suspicious_imports'])[:12])}")
    print(f"YARA:         {yara.get('backend', 'none')} · правил {yara.get('rules_compiled', 0)}"
          f" · совпадений {len(yara.get('matches') or [])}")
    print(f"Песочница:    {dynamic.get('status', 'skipped')}"
          + (f" ({dynamic.get('reason')})" if dynamic.get("reason") else ""))
    print(f"ИИ-модуль:    {ai.get('status', 'skipped')}"
          + (f" · {ai.get('verdict')} · уверенность {ai.get('confidence')}"
             if ai.get("status") == "ok" else ""))
    if ai.get("status") == "ok" and ai.get("explanation"):
        print(f"  {ai['explanation']}")
    print("-" * 62)
    print("Причины:")
    for reason in report["reasons"] or ["Явных признаков вредоносного поведения не найдено"]:
        print(f"  • {reason}")
    if disassembly and pe.get("disassembly_sample"):
        print("-" * 62)
        print("Дизассемблирование (начало секции кода):")
        for line in pe["disassembly_sample"]:
            print(f"  {line}")
    print("-" * 62)
    print(f"ВЕРДИКТ: {VERDICT_LABELS.get(report['verdict'], report['verdict'])}")
    print("=" * 62)


def main(argv: list | None = None) -> int:
    _force_utf8_console()
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose)
    target = os.path.abspath(args.target)

    settings = Settings.from_env()
    settings.use_yara = not args.no_yara
    settings.use_ai = not args.no_ai
    settings.disassembly = not args.no_disasm
    settings.sandbox.enabled = bool(args.dynamic)
    settings.sandbox.allow_unsigned = bool(args.dynamic_untrusted)
    pipeline = Pipeline(settings)

    if not os.path.exists(target):
        print(f"[ERR] Путь не существует: {target}", file=sys.stderr)
        return EXIT_CODES["ERROR"]

    if args.folder or os.path.isdir(target):
        if not os.path.isdir(target):
            print(f"[ERR] Не каталог: {target}", file=sys.stderr)
            return EXIT_CODES["ERROR"]
        reports = [item.to_dict() for item in pipeline.scan_folder(target)]
        for report in reports:
            if not args.quiet:
                print_report(report, disassembly=not args.no_disasm)
        payload: object = reports
        worst = worst_verdict([r["verdict"] for r in reports])
    else:
        report = pipeline.scan_file(target).to_dict()
        if args.quiet:
            print(f"{report['file_name']}: {report['verdict']} (score={report['score']})")
        else:
            print_report(report, disassembly=not args.no_disasm)
        payload = report
        worst = report["verdict"]

    if args.json_path:
        try:
            with open(args.json_path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2)
            print(f"Отчёт сохранён: {args.json_path}")
        except OSError as exc:
            print(f"[ERR] Не удалось сохранить отчёт: {exc}", file=sys.stderr)
            return EXIT_CODES["ERROR"]

    return EXIT_CODES.get(worst, 3)


if __name__ == "__main__":
    sys.exit(main())