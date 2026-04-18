"""AI client helpers for OpenAI-compatible gateways and local Ollama instances.

Set `AI_PROVIDER=openai-compatible` to use the standard `/chat/completions` API
with `AI_API_KEY`, `AI_BASE_URL`, and `AI_MODEL`. Set `AI_PROVIDER=ollama` to
default to `http://localhost:11434/v1` and `llama3.1` without requiring a real
API key.
"""

import json
import os
import time
from pathlib import Path

import requests


ROOT_ENV_PATH = Path(".env")
RETRYABLE_STATUS_CODES = {413, 429}
RETRY_DELAYS = (2, 4, 8)


class PayloadTooLargeError(requests.HTTPError):
    """Raised when the upstream AI gateway rejects the payload as too large."""


class RateLimitError(requests.HTTPError):
    """Raised when the upstream AI gateway rate-limits all retry attempts."""


def load_dotenv(path: Path = ROOT_ENV_PATH) -> None:
    if not path.exists():
        return

    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def get_ai_config() -> dict:
    load_dotenv()

    provider = os.getenv("AI_PROVIDER", "openai-compatible").strip() or "openai-compatible"

    if provider == "ollama":
        api_key = os.getenv("AI_API_KEY", "ollama").strip() or "ollama"
        base_url = os.getenv("AI_BASE_URL", "http://localhost:11434/v1").strip().rstrip("/")
        model = os.getenv("AI_MODEL", "llama3.1").strip() or "llama3.1"
    else:
        api_key = os.getenv("AI_API_KEY", "").strip()
        base_url = os.getenv("AI_BASE_URL", "https://api.openai.com/v1").strip().rstrip("/")
        model = os.getenv("AI_MODEL", "gpt-4o-mini").strip() or "gpt-4o-mini"

        if not api_key:
            raise RuntimeError("Missing AI_API_KEY. Set it in .env or GitHub Secrets.")

    return {
        "api_key": api_key,
        "base_url": base_url,
        "model": model,
        "provider": provider,
    }


def _raise_retry_error(error: requests.HTTPError, statuses: list[int]) -> None:
    status_set = set(statuses)
    if status_set == {413}:
        raise PayloadTooLargeError(str(error), response=error.response) from error
    if status_set == {429}:
        raise RateLimitError(str(error), response=error.response) from error
    raise error


def _post_with_retry(url: str, headers: dict, payload: dict) -> requests.Response:
    last_error = None
    statuses = []
    for attempt in range(3):
        response = requests.post(url, headers=headers, json=payload, timeout=120)
        try:
            response.raise_for_status()
            return response
        except requests.HTTPError as error:
            status_code = int(response.status_code)
            if status_code not in RETRYABLE_STATUS_CODES:
                raise

            last_error = error
            statuses.append(status_code)
            if attempt == 2:
                break
            time.sleep(RETRY_DELAYS[attempt])

    if last_error is None:  # pragma: no cover - defensive
        raise RuntimeError("AI request failed without an HTTP error.")
    _raise_retry_error(last_error, statuses)


def call_ai_json_with_metadata(system_prompt: str, user_prompt: str, max_tokens: int = 2048) -> dict:
    config = get_ai_config()
    headers = {
        "Authorization": f"Bearer {config['api_key']}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": config["model"],
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "max_tokens": max_tokens,
    }

    started_at = time.perf_counter()
    url = f"{config['base_url']}/chat/completions"
    response = None
    try:
        response = _post_with_retry(
            url,
            headers,
            {**payload, "response_format": {"type": "json_object"}},
        )
    except requests.HTTPError as error:
        status_code = int(getattr(error.response, "status_code", 0) or 0)
        if status_code not in {400, 404, 415, 422}:
            raise
        response = _post_with_retry(url, headers, payload)

    response_payload = response.json()
    content = response_payload["choices"][0]["message"]["content"]
    if isinstance(content, list):
        content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
    return {
        "result": json.loads(content),
        "response_payload": response_payload,
        "model": response_payload.get("model", config["model"]),
        "latency_ms": int((time.perf_counter() - started_at) * 1000),
    }


def call_ai_json(system_prompt: str, user_prompt: str) -> dict:
    return call_ai_json_with_metadata(system_prompt, user_prompt)["result"]
