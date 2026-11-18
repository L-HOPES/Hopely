"""Конфигурация Hopely.

Ключи никогда не хранятся в коде: они читаются из переменных окружения
(`.env` в корне проекта подхватывается автоматически). Файл `.env` и
`ключи от ии.txt` в git не попадают — см. `.gitignore`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT_DIR / "rules"
REPORTS_DIR = ROOT_DIR / "reports"

# Пороги энтропии из исследовательской части проекта.
# 7.0 — возможен упаковщик, 7.4 — критично (OBFUSCATED).
# Легитимные подписанные программы (например, notepad.exe) дают до ~7.0,
# поэтому начинать тревогу раньше нельзя — иначе ложные срабатывания.
ENTROPY_SUSPICIOUS = 7.0
ENTROPY_CRITICAL = 7.4

# Пороги итогового балла риска
SCORE_SUSPICIOUS = 25
SCORE_MALWARE = 60

# Сколько секунд песочница наблюдает за процессом (по проекту 3–5 с)
SANDBOX_WATCH_SECONDS = 4.0
SANDBOX_MEMORY_LIMIT_MB = 1024


def load_dotenv(path: Path | None = None) -> None:
    """Простой парсер `.env` без сторонних библиотек.

    Уже установленные переменные окружения не перетираются.
    """
    env_path = path or (ROOT_DIR / ".env")
    if not env_path.is_file():
        return
    try:
        raw = env_path.read_text(encoding="utf-8")
    except OSError:
        return
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on", "да"}


@dataclass
class AiConfig:
    """Параметры модуля ИИ-анализа."""

    # Ключ хранится только в переменных окружения
    api_key: str | None = os.environ.get("HOPELY_AI_KEY") or os.environ.get("GEMINI_API_KEY")
    model: str = os.environ.get("HOPELY_AI_MODEL", "gemini-2.5-flash")
    base_url: str = os.environ.get(
        "HOPELY_AI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta"
    )
    timeout_seconds: float = float(os.environ.get("HOPELY_AI_TIMEOUT", "45"))
    enabled: bool = True

    @property
    def available(self) -> bool:
        return self.enabled and bool(self.api_key)


@dataclass
class SandboxConfig:
    """Параметры песочницы (динамического анализа)."""

    # Двойной предохранитель: без флага в .env файл не запускается даже с --dynamic
    allow: bool = _env_flag("HOPELY_SANDBOX_ALLOW", False)
    enabled: bool = False
    allow_unsigned: bool = False
    watch_seconds: float = SANDBOX_WATCH_SECONDS
    memory_limit_mb: int = SANDBOX_MEMORY_LIMIT_MB

    @property
    def permitted(self) -> bool:
        return self.enabled and self.allow


@dataclass
class Settings:
    """Все настройки одного запуска сканера."""

    ai: AiConfig = field(default_factory=AiConfig)
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    rules_dir: Path = RULES_DIR
    use_yara: bool = True
    use_ai: bool = True
    disassembly: bool = True

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv()
        settings = cls()
        # Перечитываем поля после загрузки .env
        settings.ai = AiConfig(
            api_key=os.environ.get("HOPELY_AI_KEY") or os.environ.get("GEMINI_API_KEY"),
            model=os.environ.get("HOPELY_AI_MODEL", "gemini-2.5-flash"),
            base_url=os.environ.get(
                "HOPELY_AI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta"
            ),
            timeout_seconds=float(os.environ.get("HOPELY_AI_TIMEOUT", "45")),
        )
        settings.sandbox = SandboxConfig(
            allow=_env_flag("HOPELY_SANDBOX_ALLOW", False),
            watch_seconds=float(os.environ.get("HOPELY_SANDBOX_SECONDS", SANDBOX_WATCH_SECONDS)),
            memory_limit_mb=int(os.environ.get("HOPELY_SANDBOX_MEMORY_MB", SANDBOX_MEMORY_LIMIT_MB)),
        )
        return settings