"""Модуль PE-анализа (pefile + capstone).

Вскрывает заголовки PE, разбирает секцию кода, считает энтропию Шеннона,
проверяет права доступа секций и таблицу импорта (IAT) на наличие
подозрительных функций Windows API. Файл при этом не запускается.
"""

from __future__ import annotations

import hashlib
import math
import os
from datetime import datetime, timezone

from ..config import ENTROPY_CRITICAL, ENTROPY_SUSPICIOUS
from ..models import PeReport

try:  # зависимости ставятся через requirements.txt
    import pefile
except ImportError:  # pragma: no cover
    pefile = None

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
except ImportError:  # pragma: no cover
    Cs = None


# Веса подозрительных WinAPI-функций: чем выше вес, тем сильнее признак
# вредоносного поведения. Значения подобраны по типовым техникам малвари.
SUSPICIOUS_API = {
    # Инъекции кода в чужие процессы
    "virtualallocex": 20,
    "virtualalloc": 14,
    "writeprocessmemory": 22,
    "createremotethread": 22,
    "createremotethreadex": 22,
    "ntunmapviewofsection": 18,
    "queueuserapc": 16,
    "setthreadcontext": 16,
    "openprocess": 10,
    # Перехваты и скрытность
    "setwindowshookex": 14,
    "setwindowshook": 12,
    "unhookwindowshookex": 8,
    "blockinput": 10,
    # Криптография и сеть (шифровальщики, RAT, бэкдоры)
    "cryptencrypt": 12,
    "cryptgenkey": 12,
    "cryptacquirecontext": 8,
    "internetopenurl": 10,
    "urlmon": 8,
    "winexec": 12,
    "shellexecute": 8,
    # Автозапуск и закрепление в системе
    "regsetvalueex": 10,
    "createservice": 14,
    "schtasks": 10,
    # Анти-отладка
    "isdebuggerpresent": 10,
    "checkremotedebuggerpresent": 12,
    "ntqueryinformationprocess": 10,
    # Клавиатура и скриншоты
    "getasynckeystate": 12,
    "getkeystate": 10,
    "bitblt": 6,
}

MACHINE_NAMES = {
    0x014C: ("x86", CS_MODE_32 if Cs else None),
    0x8664: ("x64", CS_MODE_64 if Cs else None),
    0xAA64: ("ARM64", None),  # Capstone x86 не умеет ARM64 — дизасм пропускаем
}


class PeAnalyzer:
    """Статический разбор PE-файла."""

    def __init__(self, entropy_suspicious: float = ENTROPY_SUSPICIOUS,
                 entropy_critical: float = ENTROPY_CRITICAL,
                 disassembly: bool = True):
        self.entropy_suspicious = entropy_suspicious
        self.entropy_critical = entropy_critical
        self.disassembly = disassembly

    # ------------------------------------------------------------------ утилиты
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Энтропия Шеннона для набора байтов (0.0–8.0)."""
        if not data:
            return 0.0
        frequencies = [0] * 256
        for byte in data:
            frequencies[byte] += 1
        length = len(data)
        entropy = 0.0
        for count in frequencies:
            if count:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 2)

    @staticmethod
    def file_hashes(file_path: str) -> tuple[str, str]:
        """Вернуть (sha256, md5) содержимого файла."""
        sha = hashlib.sha256()
        md5 = hashlib.md5()
        with open(file_path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 256), b""):
                sha.update(chunk)
                md5.update(chunk)
        return sha.hexdigest(), md5.hexdigest()

    # --------------------------------------------------------------- сканирование
    def analyze(self, file_path: str) -> PeReport:
        report = PeReport()
        report.file_size_kb = round(os.path.getsize(file_path) / 1024, 2)

        if pefile is None:
            report.error = "Не установлена библиотека pefile (pip install -r requirements.txt)"
            return report

        try:
            report.sha256, report.md5 = self.file_hashes(file_path)
        except OSError as exc:
            report.error = f"Не удалось прочитать файл: {exc}"
            return report

        try:
            pe = pefile.PE(file_path, fast_load=True)
        except pefile.PEFormatError:
            # Не PE: ниже соберём только общую энтропию сырых байтов
            return self._analyze_raw(file_path, report)
        except Exception as exc:  # noqa: BLE001 - отчёт должен вернуться всегда
            report.error = f"Не удалось разобрать PE-структуру: {exc}"
            return report

        try:
            self._analyze_pe(pe, report)
        except Exception as exc:  # noqa: BLE001
            report.error = f"Ошибка разбора PE: {exc}"
        finally:
            try:
                pe.close()
            except Exception:  # noqa: BLE001
                pass
        return report

    # ------------------------------------------------------------- внутренности
    def _analyze_raw(self, file_path: str, report: PeReport) -> PeReport:
        """Файл не PE — считаем общую энтропию и возвращаем отчёт."""
        report.is_pe = False
        report.architecture = "raw"
        try:
            with open(file_path, "rb") as handle:
                raw = handle.read(1024 * 1024)
        except OSError as exc:
            report.error = f"Не удалось прочитать файл: {exc}"
            return report
        report.entropy_max = self.calculate_entropy(raw)
        report.obfuscated = report.entropy_max >= self.entropy_critical
        return report

    def _analyze_pe(self, pe, report: PeReport) -> None:
        report.is_pe = True
        machine = getattr(pe.FILE_HEADER, "Machine", 0)
        arch_name, cs_mode = MACHINE_NAMES.get(machine, (f"0x{machine:04X}", None))
        report.architecture = arch_name

        image_base = getattr(pe.OPTIONAL_HEADER, "ImageBase", 0)
        entry_rva = getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0)
        report.entry_point = f"0x{image_base + entry_rva:X}"
        timestamp = getattr(pe.FILE_HEADER, "TimeDateStamp", 0)
        if timestamp and timestamp != 0xFFFFFFFF:
            try:
                report.compile_timestamp = (
                    datetime.fromtimestamp(timestamp, tz=timezone.utc)
                    .strftime("%Y-%m-%d %H:%M UTC")
                )
            except (OSError, ValueError, OverflowError):
                report.compile_timestamp = None

        text_section = None
        for section in pe.sections:
            name = section.Name.rstrip(b"\x00").decode("ascii", errors="ignore") or "<unnamed>"
            try:
                data = section.get_data()
            except Exception:  # noqa: BLE001
                continue

            entropy = self.calculate_entropy(data)
            report.entropy_sections[name] = entropy
            report.entropy_max = max(report.entropy_max, entropy)

            # W+X-секция — признак самомодифицирующегося кода или упаковщика
            if section.IMAGE_SCN_MEM_WRITE and section.IMAGE_SCN_MEM_EXECUTE:
                report.writable_executable_sections.append(name)

            if text_section is None and (b".text" in section.Name or section.IMAGE_SCN_CNT_CODE):
                text_section = (section, data)

        report.obfuscated = report.entropy_max >= self.entropy_critical
        self._collect_imports(pe, report)

        # Дизассемблируем начало секции кода для наглядности в отчёте
        if self.disassembly and text_section and Cs and cs_mode is not None:
            section, data = text_section
            md = Cs(CS_ARCH_X86, cs_mode)
            try:
                for instr in md.disasm(data[:64], section.VirtualAddress):
                    report.disassembly_sample.append(
                        f"{hex(instr.address)}: {instr.mnemonic} {instr.op_str}".rstrip()
                    )
            except Exception:  # noqa: BLE001
                pass

    @staticmethod
    def _collect_imports(pe, report: PeReport) -> None:
        """Собрать подозрительные импорты и список DLL."""
        try:
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )
            entries = getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
        except Exception:  # noqa: BLE001
            return

        for entry in entries:
            dll = getattr(entry, "dll", b"")
            if dll:
                name = dll.decode("ascii", errors="ignore").lower()
                if name and name not in report.imported_dlls:
                    report.imported_dlls.append(name)
            for imp in getattr(entry, "imports", []):
                if not imp.name:
                    continue
                name = imp.name.decode("utf-8", errors="ignore").lower()
                if name in SUSPICIOUS_API and name not in report.suspicious_imports:
                    report.suspicious_imports.append(name)

    @staticmethod
    def import_score(imports: list) -> int:
        """Суммарный вес найденных подозрительных импортов."""
        return sum(SUSPICIOUS_API.get(name, 0) for name in imports)