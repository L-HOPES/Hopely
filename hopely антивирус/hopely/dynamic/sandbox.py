"""Изолированный запуск проверяемого файла.

Запуск выполняется только при двойном подтверждении: флаг `--dynamic`
и `HOPELY_SANDBOX_ALLOW=1` в `.env`. Файл копируется во временный каталог,
стартует приостановленным, помещается в Job Object с лимитом памяти и
запретом окон, затем возобновляется и наблюдается 3–5 секунд. После этого
всё дерево процессов уничтожается.

Это учебная песочница на средствах Windows (Job Object), а не виртуальная
машина: она снижает риск, но не даёт полной изоляции.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import tempfile
import time
from ctypes import wintypes

from ..models import DynamicReport
from .telemetry import ProcessMonitor

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

# Константы Win32
CREATE_SUSPENDED = 0x00000004
CREATE_NO_WINDOW = 0x08000000
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9
JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION_CLASS = 1
CREATE_UNICODE_ENVIRONMENT = 0x00000400


class _JobObjectBasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class _JobObjectExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JobObjectBasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class Sandbox:
    """Контролируемый запуск подозрительного файла."""

    def __init__(self, allowed: bool = False, watch_seconds: float = 4.0,
                 memory_limit_mb: int = 1024, allow_unsigned: bool = False):
        self.allowed = allowed
        self.watch_seconds = watch_seconds
        self.memory_limit_mb = memory_limit_mb
        self.allow_unsigned = allow_unsigned
        self.markers: list = []

    # ------------------------------------------------------------ проверка подписи
    @staticmethod
    def check_signature(file_path: str) -> str:
        """Проверить Authenticode-подпись: valid | unsigned | invalid | unknown."""
        try:
            quoted = file_path.replace("'", "''")
            script = (
                f"(Get-AuthenticodeSignature -FilePath '{quoted}').Status"
            )
            completed = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True,
                text=True,
                timeout=20,
            )
            status = (completed.stdout or "").strip().lower()
        except Exception:  # noqa: BLE001
            return "unknown"
        if "notsigned" in status:
            return "unsigned"
        if status.startswith("valid"):
            return "valid"
        if status:
            return "invalid"
        return "unknown"

    # ------------------------------------------------------------------- запуск
    def run(self, file_path: str) -> DynamicReport:
        report = DynamicReport()

        if psutil is None:
            report.status = "error"
            report.error = "Не установлена библиотека psutil (pip install -r requirements.txt)"
            return report
        if not self.allowed:
            report.status = "refused"
            report.reason = (
                "Динамический анализ запрещён: задайте HOPELY_SANDBOX_ALLOW=1 в .env"
            )
            return report
        if os.name != "nt":
            report.status = "refused"
            report.reason = "Песочница реализована только для Windows"
            return report

        report.signature = self.check_signature(file_path)
        if report.signature in {"unsigned", "invalid"} and not self.allow_unsigned:
            report.status = "refused"
            report.reason = (
                f"Подпись файла: {report.signature}. Запуск только с флагом "
                "--dynamic-untrusted"
            )
            return report

        workdir = tempfile.mkdtemp(prefix="hopely_sandbox_")
        target = os.path.join(workdir, os.path.basename(file_path))
        process = None
        job_handle = None
        try:
            shutil.copy2(file_path, target)
            started = time.monotonic()
            process, job_handle = self._spawn(target, workdir)
            monitor = ProcessMonitor(watch_seconds=self.watch_seconds)
            monitor.observe(process)

            report.status = "ran"
            report.duration_seconds = round(time.monotonic() - started, 2)
            report.max_threads = monitor.max_threads
            report.network_connections = monitor.network_connections
            report.child_processes = monitor.child_processes
            report.io_read_bytes = monitor.io_read_bytes
            report.io_write_bytes = monitor.io_write_bytes
            try:
                report.exit_code = process.returncode
            except Exception:  # noqa: BLE001
                report.exit_code = None
            report.markers = self._markers(report)
            report.score = min(40, 10 * len(report.markers))
        except Exception as exc:  # noqa: BLE001
            report.status = "error"
            report.error = f"Ошибка песочницы: {exc}"
        finally:
            self._terminate(process, job_handle, workdir)
        return report

    def _spawn(self, target: str, workdir: str):
        """Создать процесс приостановленным и поместить его в Job Object."""
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        job = kernel32.CreateJobObjectW(None, None)
        if job:
            limits = _JobObjectExtendedLimitInformation()
            limits.BasicLimitInformation.LimitFlags = (
                JOB_OBJECT_LIMIT_PROCESS_MEMORY
                | JOB_OBJECT_LIMIT_JOB_MEMORY
                | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            )
            limits.BasicLimitInformation.ActiveProcessLimit = 32
            limits.ProcessMemoryLimit = self.memory_limit_mb * 1024 * 1024
            limits.JobMemoryLimit = self.memory_limit_mb * 2 * 1024 * 1024
            kernel32.SetInformationJobObject(
                job,
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
                ctypes.byref(limits),
                ctypes.sizeof(limits),
            )

        creation_flags = CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT
        process = subprocess.Popen(
            [target],
            cwd=workdir,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creation_flags,
            close_fds=True,
        )

        if job:
            try:
                kernel32.AssignProcessToJobObject(job, int(process._handle))  # noqa: SLF001
            except Exception:  # noqa: BLE001
                pass

        # Снимаем приостановку: иначе файл не начнёт работу
        try:
            ntdll = ctypes.WinDLL("ntdll")
            # Главный поток — это первый поток процесса с нулевым временем,
            # надёжнее всего возобновить через NtResumeProcess
            handle = kernel32.OpenProcess(0x0800, False, process.pid)  # PROCESS_SUSPEND_RESUME
            if handle:
                ntdll.NtResumeProcess(handle)
                kernel32.CloseHandle(handle)
        except Exception:  # noqa: BLE001
            pass
        return process, job

    def _markers(self, report: DynamicReport) -> list:
        """Короткие текстовые маркеры для отчёта и ИИ."""
        markers: list = []
        if report.network_connections:
            markers.append(
                "network: "
                + ", ".join(
                    sorted({item.get("remote", "") for item in report.network_connections})
                )[:200]
            )
        if len(report.child_processes) > 2:
            markers.append(
                "child_processes: "
                + ", ".join(sorted({item.get("name", "") for item in report.child_processes}))
            )
        if report.max_threads >= 16:
            markers.append(f"threads: {report.max_threads}")
        if report.io_write_bytes >= 20 * 1024 * 1024:
            markers.append(f"disk_write: {report.io_write_bytes // (1024 * 1024)} MB")
        return markers

    @staticmethod
    def _terminate(process, job_handle, workdir: str) -> None:
        """Уничтожить дерево процессов и удалить временный каталог."""
        if process is not None:
            try:
                tree = psutil.Process(process.pid).children(recursive=True)
            except Exception:  # noqa: BLE001
                tree = []
            for child in tree:
                try:
                    child.kill()
                except Exception:  # noqa: BLE001
                    pass
            try:
                process.kill()
            except Exception:  # noqa: BLE001
                pass
            try:
                process.wait(timeout=5)
            except Exception:  # noqa: BLE001
                pass
        if job_handle:
            try:
                ctypes.WinDLL("kernel32").CloseHandle(job_handle)
            except Exception:  # noqa: BLE001
                pass
        shutil.rmtree(workdir, ignore_errors=True)