"""Hopely Launcher — графический запуск сканера Hopely (золотая тема).

Лаунчер не содержит собственной логики анализа: он вызывает
`py -m hopely` в отдельном процессе, разбирает JSON-отчёт и показывает
результаты по модулям (PE, YARA, песочница, ИИ). Работает на стандартном
tkinter, дополнительных зависимостей не требует.
"""

from __future__ import annotations

import json
import math
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_DIR = os.path.join(ROOT_DIR, "reports")

# Золотая палитра
COLORS = {
    "bg": "#120f08",
    "panel": "#1c1710",
    "panel_alt": "#262017",
    "field": "#241d12",
    "fg": "#f5e7c6",
    "muted": "#b8a374",
    "gold": "#d4af37",
    "gold_light": "#ffe38a",
    "gold_dark": "#8a6d1f",
    "border": "#3d3117",
    "ok": "#4fd18b",
    "warn": "#f0b429",
    "bad": "#ff6b5e",
}

VERDICT_STYLE = {
    "CLEAN": ("ФАЙЛ ЧИСТ", COLORS["ok"]),
    "SUSPICIOUS": ("ПОДОЗРИТЕЛЬНО", COLORS["warn"]),
    "MALWARE": ("ВРЕДОНОСНО", COLORS["bad"]),
    "ERROR": ("ОШИБКА", COLORS["bad"]),
    "UNKNOWN": ("НЕТ ДАННЫХ", COLORS["muted"]),
}

MODULE_CARDS = (("pe", "PE-АНАЛИЗ"), ("yara", "YARA"),
                ("dynamic", "ПЕСОЧНИЦА"), ("ai", "ИИ-МОДЕЛЬ"))


def mix(first: str, second: str, ratio: float) -> str:
    """Смешать два цвета #rrggbb (ratio 0 — первый, 1 — второй)."""
    ratio = max(0.0, min(1.0, ratio))
    a = [int(first[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(second[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x + (y - x) * ratio):02x}" for x, y in zip(a, b))


class GoldButton(tk.Canvas):
    """Кнопка с золотым градиентом и бликом, пробегающим при наведении."""

    def __init__(self, master, text: str, command, width: int = 150, height: int = 34,
                 primary: bool = True):
        super().__init__(master, width=width, height=height, highlightthickness=0,
                         bg=COLORS["bg"])
        self.command = command
        self.text = text
        self.primary = primary
        self._enabled = True
        self._hover = False
        self._phase = 0.0
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_click)
        self._draw()

    def _palette(self) -> tuple[str, str, str]:
        if not self.primary:
            return COLORS["panel_alt"], COLORS["gold_dark"], COLORS["fg"]
        if not self._enabled:
            return COLORS["border"], COLORS["border"], COLORS["muted"]
        return COLORS["gold"], COLORS["gold_light"], "#241a05"

    def _draw(self) -> None:
        self.delete("all")
        width = int(self.cget("width"))
        height = int(self.cget("height"))
        top, bottom, text_color = self._palette()

        for offset in range(height):
            ratio = offset / max(1, height - 1)
            self.create_line(0, offset, width, offset, fill=mix(top, bottom, ratio * 0.75))

        border = COLORS["gold_light"] if (self._hover and self._enabled) else COLORS["gold_dark"]
        self.create_rectangle(1, 1, width - 1, height - 1, outline=border, width=1)

        if self._hover and self._enabled:
            band = 26
            x = (self._phase % (width + band * 2)) - band
            for step in range(band):
                alpha = 1 - abs(step - band / 2) / (band / 2)
                if alpha > 0:
                    self.create_line(x + step, 2, x + step, height - 2,
                                     fill=mix(top, "#ffffff", 0.45 * alpha))

        self.create_text(width // 2, height // 2, text=self.text, fill=text_color,
                         font=("Segoe UI Semibold", 10))

    def _on_enter(self, _event) -> None:
        self._hover = True
        if self._enabled:
            self._animate()

    def _on_leave(self, _event) -> None:
        self._hover = False
        self._draw()

    def _on_click(self, _event) -> None:
        if self._enabled and self.command:
            self.command()

    def _animate(self) -> None:
        if not self._hover:
            return
        self._phase += 6
        self._draw()
        self.after(16, self._animate)

    def set_enabled(self, enabled: bool, text: str | None = None) -> None:
        self._enabled = enabled
        if text is not None:
            self.text = text
        self._draw()


class HopelyLauncher(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Hopely — эвристический антивирус")
        self.geometry("980x700")
        self.minsize(820, 600)
        self.configure(bg=COLORS["bg"])

        self.events: queue.Queue = queue.Queue()
        self.worker: threading.Thread | None = None
        self.last_report: dict | list | None = None
        self._glow_phase = 0.0
        self._verdict_text = ""
        self._verdict_color = COLORS["muted"]

        self._build_styles()
        self._build_ui()
        self.after(100, self._drain_events)
        self.after(60, self._animate_glow)

    # ---------------------------------------------------------------- оформление
    def _build_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Hopely.TFrame", background=COLORS["bg"])
        style.configure("Panel.TFrame", background=COLORS["panel"])
        style.configure("Hopely.TLabel", background=COLORS["bg"], foreground=COLORS["fg"],
                        font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=COLORS["bg"], foreground=COLORS["muted"],
                        font=("Segoe UI", 9))
        style.configure("Gold.TLabel", background=COLORS["bg"], foreground=COLORS["gold"],
                        font=("Segoe UI Semibold", 9))
        style.configure("Hopely.TEntry", fieldbackground=COLORS["field"],
                        foreground=COLORS["fg"], insertcolor=COLORS["gold"],
                        borderwidth=1, relief="flat", padding=9)
        style.configure("Gold.TCheckbutton", background=COLORS["bg"],
                        foreground=COLORS["muted"], font=("Segoe UI", 9))
        style.map("Gold.TCheckbutton",
                  background=[("active", COLORS["bg"])],
                  foreground=[("active", COLORS["gold_light"])])

    # ------------------------------------------------------------------ интерфейс
    def _build_ui(self) -> None:
        self.header = tk.Canvas(self, height=92, highlightthickness=0, bg=COLORS["bg"])
        self.header.pack(fill="x")

        container = ttk.Frame(self, style="Hopely.TFrame", padding=(18, 0, 18, 14))
        container.pack(fill="both", expand=True)

        path_row = ttk.Frame(container, style="Hopely.TFrame")
        path_row.pack(fill="x", pady=(0, 10))

        self.path_var = tk.StringVar()
        ttk.Entry(path_row, textvariable=self.path_var,
                  style="Hopely.TEntry").pack(side="left", fill="x", expand=True)

        GoldButton(path_row, "Обзор…", self.pick_file, 96, 36, primary=False).pack(
            side="left", padx=(8, 0))
        GoldButton(path_row, "Папка…", self.pick_folder, 96, 36, primary=False).pack(
            side="left", padx=(6, 0))
        self.scan_button = GoldButton(path_row, "СКАНИРОВАТЬ", self.start_scan, 168, 36)
        self.scan_button.pack(side="left", padx=(10, 0))

        options = ttk.Frame(container, style="Hopely.TFrame")
        options.pack(fill="x", pady=(0, 10))
        self.use_ai = tk.BooleanVar(value=True)
        self.use_yara = tk.BooleanVar(value=True)
        self.use_dynamic = tk.BooleanVar(value=False)
        ttk.Checkbutton(options, text="YARA-правила", variable=self.use_yara,
                        style="Gold.TCheckbutton").pack(side="left")
        ttk.Checkbutton(options, text="ИИ-анализ", variable=self.use_ai,
                        style="Gold.TCheckbutton").pack(side="left", padx=(14, 0))
        ttk.Checkbutton(options, text="Песочница (запускает файл)", variable=self.use_dynamic,
                        style="Gold.TCheckbutton").pack(side="left", padx=(14, 0))
        ttk.Label(options, text="Ключ ИИ читается из .env", style="Gold.TLabel").pack(
            side="right")

        self.verdict_canvas = tk.Canvas(container, height=64, highlightthickness=0,
                                        bg=COLORS["bg"])
        self.verdict_canvas.pack(fill="x")

        self.summary_label = ttk.Label(container, text="Файл не выбран", style="Muted.TLabel")
        self.summary_label.pack(anchor="w", pady=(6, 10))

        cards = ttk.Frame(container, style="Hopely.TFrame")
        cards.pack(fill="x", pady=(0, 10))
        self.card_values: dict[str, tk.Label] = {}
        for index, (key, title) in enumerate(MODULE_CARDS):
            card = tk.Frame(cards, bg=COLORS["panel"], highlightbackground=COLORS["border"],
                            highlightthickness=1)
            card.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 8, 0))
            cards.columnconfigure(index, weight=1)
            tk.Label(card, text=title, bg=COLORS["panel"], fg=COLORS["gold"],
                     font=("Segoe UI Semibold", 8)).pack(anchor="w", padx=12, pady=(9, 0))
            value = tk.Label(card, text="—", bg=COLORS["panel"], fg=COLORS["fg"],
                             font=("Segoe UI", 9), anchor="w", justify="left")
            value.pack(anchor="w", fill="x", padx=12, pady=(2, 10))
            self.card_values[key] = value

        log_frame = tk.Frame(container, bg=COLORS["panel"], highlightbackground=COLORS["border"],
                             highlightthickness=1)
        log_frame.pack(fill="both", expand=True)

        self.log = tk.Text(log_frame, bg=COLORS["panel"], fg=COLORS["fg"],
                           insertbackground=COLORS["gold"], font=("Consolas", 10),
                           relief="flat", wrap="none", padx=12, pady=10,
                           selectbackground=COLORS["gold_dark"])
        self.log.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log.yview)
        scrollbar.pack(side="right", fill="y")
        self.log.configure(yscrollcommand=scrollbar.set, state="disabled")
        self.log.tag_configure("gold", foreground=COLORS["gold_light"])

        footer = ttk.Frame(container, style="Hopely.TFrame")
        footer.pack(fill="x", pady=(10, 0))
        GoldButton(footer, "Сохранить отчёт", self.save_report, 150, 32, primary=False).pack(
            side="left")
        GoldButton(footer, "Очистить", self.clear_log, 100, 32, primary=False).pack(
            side="left", padx=(8, 0))
        ttk.Label(footer, text="Движок: hopely.pipeline (PE + YARA + песочница + ИИ)",
                  style="Muted.TLabel").pack(side="right")

        self._set_verdict("UNKNOWN")

    # ------------------------------------------------------------- золотые эффекты
    def _draw_header(self) -> None:
        canvas = self.header
        canvas.delete("all")
        width = canvas.winfo_width() or 900
        height = 92
        for y in range(height):
            canvas.create_line(0, y, width, y, fill=mix(COLORS["bg"], COLORS["panel"], y / height))

        # Пульсирующая золотая линия-разделитель
        pulse = (math.sin(self._glow_phase) + 1) / 2
        steps = 60
        points = [
            (int(index / steps * width),
             mix(COLORS["gold_dark"], COLORS["gold_light"],
                 math.sin(index / steps * math.pi) * (0.35 + 0.65 * pulse)))
            for index in range(steps + 1)
        ]
        for (x1, color), (x2, _next) in zip(points, points[1:]):
            canvas.create_line(x1, height - 2, x2, height - 2, fill=color, width=3)

        canvas.create_text(28, 34, text="HOPELY", anchor="w", fill=COLORS["gold_light"],
                           font=("Segoe UI Semibold", 26))
        canvas.create_text(30, 66, anchor="w", fill=COLORS["muted"], font=("Segoe UI", 9),
                           text="Эвристический ИИ-анализ · PE + YARA + песочница")

    def _draw_verdict(self) -> None:
        canvas = self.verdict_canvas
        canvas.delete("all")
        width = canvas.winfo_width() or 900
        height = 64
        color = self._verdict_color
        pulse = (math.sin(self._glow_phase) + 1) / 2

        for offset in range(10, 0, -1):
            shade = mix(COLORS["bg"], color, (0.10 + 0.10 * pulse) * (11 - offset) / 10)
            canvas.create_rectangle(offset, offset, width - offset, height - offset,
                                    outline=shade)
        canvas.create_rectangle(10, 8, width - 10, height - 8,
                                fill=mix(COLORS["panel"], color, 0.28),
                                outline=color, width=2)
        canvas.create_rectangle(12, 10, width - 12, height - 10,
                                outline=mix(color, "#ffffff", 0.5))
        canvas.create_text(width // 2, height // 2, text=self._verdict_text,
                           fill=COLORS["gold_light"], font=("Segoe UI Semibold", 15))

    def _animate_glow(self) -> None:
        self._glow_phase += 0.09
        self._draw_header()
        self._draw_verdict()
        self.after(60, self._animate_glow)

    # ---------------------------------------------------------------- действия
    def pick_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Выберите файл для проверки",
            filetypes=[("Исполняемые файлы", "*.exe *.dll *.sys *.scr"),
                       ("Все файлы", "*.*")],
        )
        if path:
            self.path_var.set(path)

    def pick_folder(self) -> None:
        path = filedialog.askdirectory(title="Выберите папку для проверки")
        if path:
            self.path_var.set(path)

    def start_scan(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        target = self.path_var.get().strip().strip('"')
        if not target:
            messagebox.showwarning("Hopely", "Сначала выберите файл или папку.")
            return
        if not os.path.exists(target):
            messagebox.showerror("Hopely", f"Путь не найден:\n{target}")
            return
        if self.use_dynamic.get() and not messagebox.askyesno(
            "Hopely · песочница",
            "Динамический анализ ЗАПУСТИТ проверяемый файл в контейнере Job Object.\n\n"
            "Это учебная песочница, а не виртуальная машина. Продолжить?",
        ):
            return

        self.last_report = None
        self._set_verdict("UNKNOWN")
        self.scan_button.set_enabled(False, "СКАНИРОВАНИЕ…")
        self.log_write(f"\n[{datetime.now():%H:%M:%S}] Запуск анализа: {target}", tag="gold")

        self.worker = threading.Thread(target=self._run_scanner, args=(target,), daemon=True)
        self.worker.start()

    def _run_scanner(self, target: str) -> None:
        """Выполнить сканер отдельным процессом, чтобы не блокировать UI."""
        os.makedirs(REPORT_DIR, exist_ok=True)
        json_path = os.path.join(REPORT_DIR, "last_report.json")
        command = [sys.executable, "-m", "hopely", "--target", target, "--json", json_path]
        if not self.use_yara.get():
            command.append("--no-yara")
        if not self.use_ai.get():
            command.append("--no-ai")
        if self.use_dynamic.get():
            command += ["--dynamic", "--dynamic-untrusted"]
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True, encoding="utf-8",
                errors="replace", cwd=ROOT_DIR,
            )
        except Exception as exc:  # noqa: BLE001
            self.events.put(("error", f"Не удалось запустить сканер: {exc}"))
            return

        report = None
        if os.path.exists(json_path):
            try:
                with open(json_path, "r", encoding="utf-8") as handle:
                    report = json.load(handle)
            except (OSError, json.JSONDecodeError):
                report = None

        self.events.put(("done", {
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "code": completed.returncode,
            "report": report,
        }))

    def save_report(self) -> None:
        if self.last_report is None:
            messagebox.showinfo("Hopely",
                                "Отчёт ещё не сформирован — сначала выполните сканирование.")
            return
        path = filedialog.asksaveasfilename(
            title="Сохранить отчёт", defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialfile=f"hopely_report_{datetime.now():%Y%m%d_%H%M%S}.json",
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(self.last_report, handle, ensure_ascii=False, indent=2)
        except OSError as exc:
            messagebox.showerror("Hopely", f"Не удалось сохранить файл:\n{exc}")
            return
        self.log_write(f"[OK] Отчёт сохранён: {path}")

    def clear_log(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    # ---------------------------------------------------------------- обработка
    def _drain_events(self) -> None:
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "done":
                    self._on_scan_done(payload)
                elif kind == "error":
                    self.log_write(f"[ERR] {payload}")
                    self._set_verdict("ERROR")
                    self._reset_button()
        except queue.Empty:
            pass
        self.after(100, self._drain_events)

    def _on_scan_done(self, payload: dict) -> None:
        self._reset_button()
        report = payload.get("report")
        self.last_report = report

        if payload.get("stdout"):
            for line in payload["stdout"].rstrip().splitlines():
                tag = "gold" if line.startswith("ВЕРДИКТ") else None
                self.log_write(line, tag=tag)
        stderr = (payload.get("stderr") or "").strip()
        if stderr:
            self.log_write(f"[stderr] {stderr.splitlines()[-1]}")

        if isinstance(report, list):
            if not report:
                self._set_verdict("UNKNOWN")
                self.summary_label.configure(text="В папке не найдено подходящих файлов")
                return
            worst = max(report, key=lambda item: item.get("score", 0))
            self._set_verdict(worst.get("verdict", "UNKNOWN"))
            infected = sum(1 for item in report
                           if item.get("verdict") in ("SUSPICIOUS", "MALWARE"))
            self.summary_label.configure(
                text=f"Просканировано файлов: {len(report)} · проблемных: {infected}")
            self._fill_cards(worst)
            return

        if isinstance(report, dict):
            self._set_verdict(report.get("verdict", "UNKNOWN"))
            self.summary_label.configure(
                text=(f"{report.get('file_name', '')} · балл риска {report.get('score', 0)} · "
                      f"энтропия {report.get('entropy_max', 0)} · "
                      f"архитектура {report.get('architecture', '')}"))
            self._fill_cards(report)
            return

        self._set_verdict("ERROR" if payload.get("code") else "UNKNOWN")
        self.summary_label.configure(text=f"Сканер завершился с кодом {payload.get('code')}")

    def _fill_cards(self, report: dict) -> None:
        """Заполнить карточки модулей данными отчёта."""
        modules = report.get("modules") or {}
        pe = modules.get("pe") or {}
        yara = modules.get("yara") or {}
        dynamic = modules.get("dynamic") or {}
        ai = modules.get("ai") or {}

        imports = pe.get("suspicious_imports") or []
        self.card_values["pe"].configure(
            text=(f"энтропия {pe.get('entropy_max', 0)}\n"
                  f"импортов API: {len(imports)}\n"
                  f"{'OBFUSCATED' if pe.get('obfuscated') else 'структура в норме'}"))
        self.card_values["yara"].configure(
            text=(f"движок {yara.get('backend', 'none')}\n"
                  f"правил {yara.get('rules_compiled', 0)}\n"
                  f"совпадений {len(yara.get('matches') or [])}"))
        self.card_values["dynamic"].configure(
            text=(f"статус {dynamic.get('status', 'skipped')}\n"
                  f"потоков {dynamic.get('max_threads', 0)}\n"
                  f"сетевых {len(dynamic.get('network_connections') or [])}"))
        if ai.get("status") == "ok":
            ai_text = (f"{ai.get('verdict')} · {ai.get('confidence')}\n"
                       f"{ai.get('threat_family') or 'семейство не определено'}")
        else:
            ai_text = f"{ai.get('status', 'skipped')}\n{(ai.get('error') or 'не использовался')[:64]}"
        self.card_values["ai"].configure(text=ai_text)

    def _reset_button(self) -> None:
        self.scan_button.set_enabled(True, "СКАНИРОВАТЬ")

    def _set_verdict(self, verdict: str) -> None:
        text, color = VERDICT_STYLE.get(verdict, VERDICT_STYLE["UNKNOWN"])
        self._verdict_text = text
        self._verdict_color = color
        self._draw_verdict()

    def log_write(self, message: str, tag: str | None = None) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", message + "\n", tag or ())
        self.log.see("end")
        self.log.configure(state="disabled")


def main() -> None:
    app = HopelyLauncher()
    app.mainloop()


if __name__ == "__main__":
    main()