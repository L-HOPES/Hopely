"""Сбор поведенческих данных о запущенном процессе (psutil).

Следит за деревом процессов и фиксирует деструктивные маркеры:
интенсивность дискового ввода-вывода (шифровальщики), открытые сетевые
сокеты (бэкдоры и RAT) и аномальное число потоков (инъекции кода).
"""

from __future__ import annotations

import time

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


class ProcessMonitor:
    """Наблюдение за процессом и его потомками в течение заданного времени."""

    def __init__(self, watch_seconds: float = 4.0, poll_interval: float = 0.25):
        self.watch_seconds = watch_seconds
        self.poll_interval = poll_interval
        self.max_threads = 0
        self.network_connections: list = []
        self.child_processes: list = []
        self.io_read_bytes = 0
        self.io_write_bytes = 0

    # ------------------------------------------------------------------ утилиты
    def _tree(self, process) -> list:
        """Процесс и все его потомки (psutil.Process)."""
        tree = [process]
        try:
            tree.extend(process.children(recursive=True))
        except Exception:  # noqa: BLE001
            pass
        return tree

    def _collect_connections(self, tree: list) -> None:
        for proc in tree:
            try:
                for conn in proc.net_connections(kind="inet"):
                    if not conn.raddr and conn.status != psutil.CONN_LISTEN:
                        continue
                    remote = (
                        f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "listen"
                    )
                    entry = {"pid": proc.pid, "process": self._name(proc),
                             "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                             "remote": remote, "status": conn.status}
                    if entry not in self.network_connections:
                        self.network_connections.append(entry)
            except Exception:  # noqa: BLE001 - процесс мог завершиться
                continue

    @staticmethod
    def _name(proc) -> str:
        try:
            return proc.name()
        except Exception:  # noqa: BLE001
            return "unknown"

    # --------------------------------------------------------------------- цикл
    def observe(self, process) -> None:
        """Крутиться `watch_seconds`, собирая метрики, пока процесс жив."""
        if psutil is None:
            return
        deadline = time.monotonic() + self.watch_seconds
        seen: list = []
        while time.monotonic() < deadline:
            if not process.is_running():
                break
            tree = self._tree(process)
            for proc in tree:
                try:
                    threads = proc.num_threads()
                    self.max_threads = max(self.max_threads, threads)
                except Exception:  # noqa: BLE001
                    pass
                if proc.pid != process.pid:
                    name = self._name(proc)
                    if name not in seen:
                        seen.append(name)
                        self.child_processes.append({"pid": proc.pid, "name": name})
            self._collect_connections(tree)
            time.sleep(self.poll_interval)

        self._collect_connections(self._tree(process))
        try:
            counters = process.io_counters()
            self.io_read_bytes = int(getattr(counters, "read_bytes", 0))
            self.io_write_bytes = int(getattr(counters, "write_bytes", 0))
        except Exception:  # noqa: BLE001
            pass