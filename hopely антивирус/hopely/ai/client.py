"""ИИ-анализ итогового отчёта без сторонних SDK.

Клиент общается с моделью по HTTP через стандартный `urllib` — никаких
`google-genai` и прочих обёрток. Адрес, модель и ключ берутся из `.env`
(`HOPELY_AI_BASE_URL`, `HOPELY_AI_MODEL`, `HOPELY_AI_KEY`), ключ никогда
не хранится в коде.

Контракт запроса — стандартный для Gemini-совместимых API:

    POST {base_url}/models/{model}:generateContent?key=...
    {"contents": [...], "generationConfig": {...}}

Модель возвращает строго JSON по схеме `AiVerdict`.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from ..models import AiVerdict

DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"

SYSTEM_PROMPT = (
    "Ты — ИИ-модуль антивируса Hopely. На вход приходит JSON-отчёт статического "
    "анализа PE-файла, совпадения YARA и (если был) результат песочницы. "
    "Оцени данные как аналитик вредоносного ПО: определи вердикт, укажи "
    "семейство угрозы, объясни 2-4 ключевых признака и оцени риск ложного "
    "срабатывания (легитимные упакованные программы тоже бывают с высокой "
    "энтропией). Отвечай ТОЛЬКО валидным JSON без markdown-разметки по схеме:\n"
    "{\n"
    '  "verdict": "CLEAN | SUSPICIOUS | MALWARE",\n'
    '  "confidence": 0.0,\n'
    '  "threat_family": "строка",\n'
    '  "explanation": "строка",\n'
    '  "key_signals": ["строка"],\n'
    '  "false_positive_risk": "low | medium | high",\n'
    '  "yara_rules": ["текст YARA-правила, если нужна дополнительная проверка"]\n'
    "}"
)


class AiClientError(RuntimeError):
    """Модель недоступна или ответила некорректно."""


class ChatClient:
    """Минимальный HTTP-клиент Gemini-совместимого generateContent API."""

    def __init__(self, api_key: str | None = None, model: str = "gemini-2.5-flash",
                 base_url: str = "",
                 timeout: float = 45.0):
        self.api_key = api_key
        self.model = model
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self.timeout = timeout

    @classmethod
    def from_config(cls, config) -> "ChatClient":
        """Собрать клиент из AiConfig (ключ берётся только из окружения)."""
        return cls(
            api_key=config.api_key,
            model=config.model,
            base_url=config.base_url,
            timeout=config.timeout_seconds,
        )

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def _endpoint(self) -> str:
        model = urllib.parse.quote(self.model, safe="")
        query = urllib.parse.urlencode({"key": self.api_key or ""})
        return f"{self.base_url}/models/{model}:generateContent?{query}"

    def generate(self, prompt: str, system_prompt: str = SYSTEM_PROMPT) -> str:
        """Отправить запрос и вернуть текстовый ответ модели."""
        if not self.api_key:
            raise AiClientError(
                "Не задан ключ ИИ: добавьте HOPELY_AI_KEY в .env "
                "(ключ берётся только из переменных окружения)"
            )
        payload = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "responseMimeType": "application/json",
            },
        }
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            self._endpoint(),
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:400]
            raise AiClientError(f"HTTP {exc.code}: {self._short_error(detail)}") from exc
        except urllib.error.URLError as exc:
            raise AiClientError(f"Нет связи с моделью: {exc.reason}") from exc
        except TimeoutError as exc:
            raise AiClientError("Модель не ответила вовремя") from exc
        return self._extract_text(raw)

    @staticmethod
    def _short_error(detail: str) -> str:
        """Вытащить человекочитаемое сообщение из ошибки API."""
        try:
            parsed = json.loads(detail)
            message = (parsed.get("error") or {}).get("message")
            if message:
                return str(message)[:300]
        except json.JSONDecodeError:
            pass
        return detail[:300]

    @staticmethod
    def _extract_text(raw: str) -> str:
        """Достать текст из ответа generateContent."""
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AiClientError("Ответ модели не является JSON") from exc
        candidates = parsed.get("candidates") or []
        if not candidates:
            error = parsed.get("error") or {}
            raise AiClientError(
                error.get("message") or "Модель вернула пустой ответ (возможно, блокировка)"
            )
        parts = (candidates[0].get("content") or {}).get("parts") or []
        text = "".join(part.get("text", "") for part in parts if isinstance(part, dict))
        if not text.strip():
            raise AiClientError("В ответе модели нет текста")
        return text